# 작업 계획서: 전체 코드 적대적 리뷰 및 버그 수정

- 작성일: 2026-08-11
- 상태: 완료
- 관련 문서: [[docs/architecture.md]], [[docs/product-design.md]]

## 1. 목표 / 배경

꿀보 요청: 문서 파악 후 전체 코드를 적대적 리뷰 모드로 검토하고 버그를 수정한다.

프로젝트는 Tauri UI + Rust command + C++ native helper/controller/agent/collector 구조의 Windows API 모니터다. 핵심 위험 경로는 주입, 공유 메모리 링버퍼, 에이전트 훅, 세션/daemon 수명 관리다.

## 2. 범위

- 포함:
  - 문서 기반 현재 상태 파악
  - hand-written native / Rust / UI 경로의 정확성·동시성·수명 버그 검토
  - 확정된 high/medium 버그 수정 및 가능하면 smoke 검증
- 제외:
  - 생성된 훅/메타데이터 대량 재생성
  - 신규 기능 추가
  - 보호 프로세스/크로스 비트니스 등 의도적 미지원 경로
- 전제 조건 / 의존성:
  - native x64 빌드 가능 환경

## 3. 접근안 비교

| 안 | 요약 | 장점 | 단점 | 리스크 |
|---|---|---|---|---|
| A | 핫패스/수명/ID 생성 등 확정 버그만 즉시 수정 | 빠른 안정성 개선 | 전수 리뷰 깊이 제한 | 잔여 이슈 가능 |
| B | 전 파일 리라이트 수준 리팩터 | 구조 정리 | 범위 과다, 회귀 위험 | 높음 |

**선택: A**

선택 근거: 요청은 버그 수정이며, 17k+ 라인 Agent/Controller를 한 번에 재작성하면 회귀 비용이 크다. 증거 가능한 결함부터 고치고 문서로 잔여 리스크를 남긴다.

## 4. 구현 단계

1. 문서/아키텍처 파악 및 핵심 경로 식별
2. Protocol/Transport/Agent/Controller/Helper/UI 적대적 검토
3. 확정 버그 수정
4. 빌드/스모크 검증
5. 계획 문서에 결과 반영

## 5. 위험 및 실패 경로

- 위험: transport 프로토콜 변경이 smoke와 어긋날 수 있음
- 실패 시 증상: consumer stall, mapping 충돌, UI/helper 세션 혼선, join timeout 후 terminate
- 롤백: 해당 파일 diff 단위 되돌림
- 호환성: ABI version 유지, 기존 session schema 불변

## 6. 검증 방법

- native collector smoke (shared transport reader / backpressure)
- 가능하면 기존 native smoke 일부
- 성공 기준: 수정 경로 컴파일, 관련 smoke 통과, 기존 계약 유지

## 7. 오픈 이슈

- [ ] Agent DllMain DETACH 시 IAT 미복원 (stop 없이 FreeLibrary 시 크래시 가능) — 설계 경계 여부 확인
- [ ] g_operationId / FillAgentState 읽기 경합 (query 중 reset)
- [ ] JSON hand parser key 첫 매칭 취약성 (문자열 내부 키 오인) — 범위 큰 재작업

## 8. 진행 로그

- 2026-08-11: 문서/구조 파악. 확정 버그 발견·수정·빌드/스모크 검증 완료.

### 확정 결함 목록 및 조치

| ID | 심각도 | 위치 | 요약 | 조치 |
|---|---|---|---|---|
| B1 | High | helper `NewOperationId` / Rust `new_operation_id` | tick/ms 단위 ID 충돌 → transport/cancel 이름 충돌 | QPC+Interlocked 시퀀스 / AtomicU64 시퀀스 추가 |
| B2 | High | `CreateSharedTransport` | `ERROR_ALREADY_EXISTS` 시 기존 mapping 재사용·memset | ALREADY_EXISTS 시 생성 실패 |
| B3 | High | `ThreadedSharedTransportReader::Join`/destructor | timeout 후 joinable thread → `std::terminate` | destructor는 Join(0) 무한 대기, timeout 시 joinable 유지 |
| B4 | Medium | Agent `OpenTransport` | MaxCapacity/HeaderSize 미검증 → OOB 가능 | HeaderSize/MaxCapacity 검증 추가 |
| B5 | Medium | Agent `ReserveTransportRecord` | CAS 실패 시 producer hole → consumer 영구 stall | poison commit + State 유지 필드 초기화 |
| B6 | Medium | Cancel `CreateEventW` | 기존 이름 이벤트 재사용 시 잔여 signal 가능 | `ResetEvent` 강제 |
| B7 | Medium | Transport Sequence x86 | 비원자 64-bit Sequence 읽기/쓰기 찢김 가능 | Interlocked load/store 사용 |

### 검증

- `npm run native:configure` / `npm run native:build` 성공
- `knmon-collector smoke-backpressure` 통과
- `knmon-collector smoke-shared-transport-reader` 통과
- `knmon-collector smoke-threaded-session-reader` 통과
- `knmon-native-helper list-targets` 정상
- `cargo check -p knmon-tauri` 통과

### 잔여 리스크 (미수정)

1. Agent `DllMain` DETACH에서 IAT 미복원 — `KnMonAgentStop` 없이 unload 시 크래시 가능. 현재 제어 경로는 stop 후 detach를 전제로 함.
2. `g_operationId` 등 일부 전역 상태의 약한 동기화.
3. helper JSON hand-parser는 첫 키 매칭 기반이라 문자열 내부 오인 가능. 계약 내부 페이로드에서는 실사용 리스크 제한적.
