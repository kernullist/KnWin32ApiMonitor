# 호출 시간과 오류 상태 계약

네이티브 x86/x64 Agent의 transport ABI는 6이다. 이전 ABI의 Agent와 helper를 섞어 사용하면 초기화 단계에서 거부한다.

## 시간

Host는 수집을 시작하기 전에 QPC–UTC 기준점을 고정한다. `QPC → GetSystemTimePreciseAsFileTime → QPC`를 8회 측정하고 가장 짧은 구간의 QPC 중간값을 선택한다. 모든 이벤트의 `timing`에 같은 `qpcFrequency`, `qpcBase`, `utcBaseFileTime`, `anchorSpanQpc`를 보관한다. Process tree의 자식 캡처는 공통 기준점을 사용한다.

`startQpc`, `endQpc`와 기준점의 64비트 값은 JSON의 10진 문자열이다. Rust와 TypeScript도 문자열을 유지한다. 상대 시각은 `floor((startQpc - qpcBase) * 1000000 / qpcFrequency) / 1000` ms이며, 정수 나눗셈 전에 범위를 검사한다. UI, JSONL/KNAPM 저장·재생과 SQLite index가 같은 값을 사용한다. SQLite/Rust의 상대 시각 필드는 소수 ms를 보존한다.

- `timestampUtc`: 고정 기준점으로 환산한 호출 시작 시각. 나중의 시스템 시각 변경으로 기존 이벤트가 이동하지 않는다.
- `collectedAtUtc`: host가 이벤트를 변환한 실제 UTC 시각.
- `durationUs`: QPC 구간의 정수 microsecond 값. `timing.durationScope`는 `original_call_with_error_state_preservation`이다. 구간에는 원본 호출과 오류 상태 복원·스냅샷 비용이 포함되며, 디코딩·record 기록은 제외한다.
- `anchorSpanQpc`: UTC 기준점을 읽는 동안의 QPC 구간 폭. 소수 7자리 UTC 표현 자체가 100 ns 측정 정확도를 보장하지는 않는다.

QPC는 시스템 UTC 시각과 독립적이다. 다른 스레드에서 ±1 tick 차이인 값은 순서를 확정할 수 없으며, transport sequence는 기록 예약 순서다. 호출 시작 순서와 구분해야 한다. [Microsoft QPC 설명](https://learn.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps)

원시 QPC가 없는 이전 Agent 이벤트를 변환할 때는 `timeSource=unavailable`, 상대 시각 0으로 표시한다. sequence에서 시간을 만들지 않는다. 이전에 저장된 trace의 상대 시각은 유지하지만 QPC 검증을 소급해서 주장하지 않는다. 새 입력의 역전 구간, 기준점 이전 시각, 잘못된 숫자 문자열, 계산 결과와 다른 상대 시각·duration은 거부한다. Host는 미래의 QPC 및 duration 불일치도 transport 손상으로 처리한다.

## 오류와 반환값

원본 호출 전에 진입 시점의 Win32 오류 상태를 복원하고, 반환 직후 상태를 보관한다. RAII 정리는 수집 코드가 종료된 뒤 원본의 상태를 복원한다. Winsock 호출은 `WSAGetLastError`와 `WSASetLastError`를 함께 사용한다. 원본의 C++ 예외와 SEH는 유지하며 `/EHa` 경계에서 lease와 오류 상태를 정리한다. Record가 가득 찬 경우에도 같은 규칙을 적용한다. [Winsock 오류 조회 계약](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsagetlasterror)

| 필드 | 의미 |
|---|---|
| `rawReturnValue`, `rawReturnBits` | 원본 반환 비트와 폭. BOOL의 2 같은 비정규 참값도 보존한다. |
| `rawLastErrorCode` | 원본이 남긴 Win32 오류 상태. 성공 여부와 무관한 원시 값이다. |
| `rawWinsockErrorCode`, `winsockErrorSampled` | Winsock 오류 상태와 실제 조회 여부. 조회하지 않은 0을 성공 증거로 취급하지 않는다. |
| `errorDomain` | `win32`, `winsock`, `ntstatus`, `hresult`, `none`. |
| `successPredicate` | 적용한 반환값 판정 규칙. |
| `outcome` | `success`, `failure`, `pending`, `unknown`. |
| `errorValidity` | `valid`, `not_applicable`, `unspecified`, `unavailable`. |
| `hasError`, `lastErrorCode`, `lastErrorMessage` | 판정된 실패의 표시용 정보. 원시 상태와 별개다. |

HRESULT는 `SUCCEEDED`, NTSTATUS는 `NT_SUCCESS` 의미를 사용한다. `S_FALSE`는 성공이고 `STATUS_PENDING`과 ReadFile/WriteFile의 `ERROR_IO_PENDING`은 pending이다. `WSAStartup`/`getaddrinfo`는 반환 상태를 사용한다. `WSARevertImpersonation`은 DLL 이름이 Fwpuclnt여도 Winsock 오류를 조회한다. [Microsoft 계약](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-wsarevertimpersonation)

정상적인 null/0과 실패가 겹치는 조회 API나 검증된 판정 규칙이 없는 API는 `unknown`으로 남길 수 있다. 남아 있는 last-error만으로 실패를 만들지 않는다. 성공한 CreateFile이 남긴 `ERROR_ALREADY_EXISTS`도 원시 값으로 보존한다. 상태 종류와 판정은 host의 지원 API 메타데이터에서 결정하며 Target이 보낸 표시용 문자열에서 결정하지 않는다.

## 실행 검증

```powershell
ctest --test-dir build/native-msvc -C Debug --output-on-failure
node tools/session-validator/validate-capture-clock.mjs build/native-msvc/Debug/knmon-capture-semantics-test.exe
./tools/native-smoke/saved-error-session-smoke.ps1 -BuildDir build/native-msvc/Debug
node tools/session-validator/validate-capture-semantics.mjs <printed-session-directory>
npm run json:sessions:validate -- --helper build/native-msvc/Debug/knmon-native-helper.exe
cargo test --manifest-path crates/knmon-tauri/Cargo.toml --lib
```

동일 시험을 x86에서도 실행한다. `capture-delayed-collector`는 실제 Agent의 이벤트를 수집하면서 첫 batch 이후 host를 750 ms 지연시킨다. 별도 BigInt oracle은 장시간 uptime, 매우 큰 frequency, overflow, 반올림 경계를 검사한다. 세션 비교기는 native 시간 계산, UI 변환, 저장·재생 필드를 독립적으로 비교한다. 전체 지원 API의 모든 입력 조합에 대한 ABI·동작 검증은 별도 differential corpus의 범위다.
