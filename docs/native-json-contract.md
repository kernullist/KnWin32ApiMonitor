# Native JSON 입력 계약

Controller와 native helper는 `knmon-json`의 불변 `JsonDocument`를 사용한다. 파싱된 자식 객체는 원본 문서의 소유권을 공유하므로 부모 view를 해제해도 유효하다. 문자열에서 키를 검색하거나 숫자를 직접 누적하던 parser는 제거했다. Agent DLL에는 JSON parser를 링크하지 않는다.

의존성은 [nlohmann/json 3.12.0](https://github.com/nlohmann/json/releases/tag/v3.12.0)이다. 배포 헤더의 SHA-256을 CMake에서 확인하고, 원본과 MIT 라이선스를 `native/third-party/nlohmann`에 보관한다. 빌드 중 다운로드는 없다. 중복 키는 [공식 parsing callback](https://json.nlohmann.me/features/parsing/parser_callbacks/)에서 DOM에 덮어쓰기 전에 거부한다.

## 크기 제한

| 입력 | 문서 바이트 | 문자열/키의 UTF-8 바이트 | 중첩 container 깊이 | container 항목 | 전체 값 |
|---|---:|---:|---:|---:|---:|
| Manifest, index, catalog, daemon 레코드 | 8 MiB | 256 KiB | 32 | 65,536 | 250,000 |
| Agent pipe 메시지 | 1 MiB | 64 KiB | 16 | 4,096 | 16,384 |
| 저장된 JSONL 한 행 | 1 MiB | 256 KiB | 32 | 65,536 | 250,000 |

JSON 문서는 파일을 읽는 단계에서도 8 MiB로 제한한다. JSONL 및 chunk 파일의 읽기 제한은 64 MiB이며, JSONL 한 파일은 250,000행과 전체 값 1,000,000개 이하여야 한다. 일괄 replay도 여러 chunk를 합친 결과에 같은 바이트/행/값 제한을 적용한다. 한도를 초과하면 실패를 반환한다. 대용량 재생의 향후 스트리밍 경로와 이 일괄 반환 경로를 구분한다.

## 구조와 타입

- UTF-8만 허용한다. BOM, 잘못된 UTF-8, 짝이 없는 surrogate, raw/escaped NUL, trailing content, comment, trailing comma를 거부한다.
- 같은 객체의 중복 키는 escape를 해석한 이름으로 검사한다. 서로 다른 객체의 같은 키는 허용하며, 조회는 해당 객체의 직계 멤버만 대상으로 한다.
- 문자열, boolean, unsigned integer, 객체, 배열을 변환 없이 검사한다. unsigned integer 필드는 음수, `-0`, 소수점 및 지수 표기, 문자열 숫자를 거부한다. UInt32/UInt64의 범위를 검사한 뒤 변환한다.
- 선택 필드가 없으면 문서화된 기본값을 사용한다. 존재하는 필드의 잘못된 타입을 기본값으로 바꾸지는 않는다. `null`은 trace의 `error`처럼 명시적으로 nullable인 필드에서만 허용한다.
- Trace의 `error` 객체는 문자열 `kind`, `code`, `message`를 갖는다. `code`는 `0x00000005` 같은 표시 문자열이며 Agent 원시 오류 정수와 구분한다.
- Agent envelope의 schemaVersion, messageType, operationId, pid, tid, timestampUtc, sequence가 필수다. HELLO, shutdown, loss, API call 및 resolver 메시지의 소비 필드를 검사한다. HELLO의 누락 값을 예상 대상 정보로 채우지 않는다.
- KNAPM의 finalized와 chunk identity/range/hash 필드는 필수다. legacy JSONL manifest에는 finalized가 없을 수 있다. Manifest의 알려진 필드는 제어 분기에 들어가기 전에 타입을 검사한다. owner 생략과 빈 owner 객체를 구분한다.
- 알려지지 않은 필드는 구조·문자열·크기 검사를 거쳐 보존할 수 있다. 새로운 필드를 소비할 때는 그 필드의 타입 계약을 추가해야 한다.

잘못된 pipe 입력은 `agent_protocol_invalid`로 처리한다. 저장 파일은 validation error 또는 `invalid_json` 실패를 반환한다. Daemon registry 스캔은 손상된 개별 레코드를 malformed 상태로 남기고 다른 레코드를 계속 검사한다. 파일을 다시 읽는 replay/index 경로에서도 검증한다. SHA-256 일치 자체를 JSON의 유효성이나 작성자 인증으로 취급하지 않는다.

Host가 process handle로 종료를 확인한 세션은 `shutdownEvidence: "released_by_process_exit"`를 저장한다. 이 세션은 Agent 종료 메시지 없이도 재생할 수 있다. 이 표시는 주소 공간 회수의 근거이며 IAT 복구나 이벤트 손실 없음의 증거가 아니다. 저장된 표시는 파일 작성자 인증을 제공하지 않는다.

## 검증

`bounded-json` CTest는 원문 F06 반례, Unicode, 숫자 범위, 필수 필드, view 수명과 제한 경계를 검사한다. 별도 Node 검증기는 [Microsoft jsonc-parser](https://github.com/microsoft/node-jsonc-parser)의 strict parsing/visitor와 `JSON.parse`를 사용한다. 중복 키, 원문 숫자 token 및 Unicode를 보존해 native 결과와 비교한다. UInt64 비교에는 BigInt를 사용해 JavaScript Number의 반올림을 피한다. jsonc-parser 3.3.1은 개발 의존성으로 고정한다.

```powershell
ctest --test-dir build/native-msvc -C Debug --output-on-failure
npm run json:native:validate -- --probe build/native-msvc/Debug/knmon-bounded-json-test.exe
npm run json:sessions:validate -- --helper build/native-msvc/Debug/knmon-native-helper.exe
npm run sessions:validate
./tools/native-smoke/saved-error-session-smoke.ps1 -BuildDir build/native-msvc/Debug
```

동일 검사를 `build/native-msvc-x86`에서도 실행한다. 세션 검사는 기존 정상/손상 fixture와 추가 변형을 실제 helper의 validate/replay 명령에 넣으며, `build/g05-json-session-*`에 사용한 입력과 결과를 남긴다.
