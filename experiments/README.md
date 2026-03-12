# A2A Push Notification 보안 실험

A2A Python SDK의 Push Notification 경로에서 발생하는 보안 위협을 분석하고,
JWT 기반 인증 방안을 구현·검증하는 실험 코드입니다.

---

## 연구 배경

A2A v1.0 명세 13.2절은 수신 에이전트의 `task_id` 검증을 명시적으로 요구하지만,
공식 Python SDK(a2a-sdk v0.3.25)의 `BasePushNotificationSender`는 이를 구현하지 않습니다.
본 실험은 이 명세-구현 간 gap을 분석하고 레퍼런스 구현을 제안합니다.

---

## 전체 구조

```
test_client_send.py
    └─► Agent Server (port 9999)          run_agent_server.py
              └─► SecurePushNotificationSender
                        └─► Webhook Receiver (port 8000)    webhook_receiver.py
                                  └─► JWT 검증 + task_id 바인딩 + replay 방지
```

---

## 파일 설명

### SDK 확장 (src/)

#### `src/a2a/server/tasks/secure_push_notification_sender.py`
`BasePushNotificationSender`를 상속하여 push 전송 시 JWT를 자동 첨부합니다.

- 알고리즘: HS256
- JWT claims: `iss`, `aud`, `iat`, `exp`, `jti`, `task_id`
- 시크릿: 환경변수 `A2A_PUSH_JWT_SECRET`

```python
push_sender = SecurePushNotificationSender(
    httpx_client=http_client,
    config_store=push_config_store,
    issuer='agentB',
    audience='agentA-webhook',
    ttl_seconds=60,
)
```

---

### 실험 스크립트 (experiments/)

#### `run_agent_server.py`
`SecurePushNotificationSender`를 연동한 HelloWorld 에이전트 서버 (port 9999)

에이전트 실행 흐름:
1. `TaskStatusUpdateEvent(working)` 발행
2. `Message("Hello World")` 발행
3. `TaskStatusUpdateEvent(completed, final=True)` 발행
→ 2, 3에서 각 1회씩 push notification 전송 (총 2회)

#### `webhook_receiver.py`
JWT를 검증하는 FastAPI 기반 webhook 수신 서버 (port 8000)

엔드포인트:
- `POST /webhook` — JWT 검증 엔드포인트 (제안 방식)
- `POST /webhook-plain` — 인증 없이 수락 (성능 측정용, 기존 방식)
- `GET /health` — 상태 확인

검증 흐름:
```
POST /webhook
    ├─ 1. Authorization: Bearer 헤더 확인
    ├─ 2. JWT 서명 검증 (HS256)
    ├─ 3. exp 만료 검증
    ├─ 4. jti 캐시 조회 (replay 방지)
    ├─ 5. task_id 클레임 추출
    └─ 6. 구독 목록과 task_id 일치 확인 (task binding)
```

#### `test_client_send.py`
`message/send` JSON-RPC를 호출하는 통합 흐름 확인용 클라이언트

- `blocking: false`로 요청 → 서버 즉시 `working` 반환
- 백그라운드에서 에이전트 완료 후 webhook으로 push 전송

#### `test_security_cases.py`
논문 3.4절 공격 시나리오별 방어 검증 (a2a-sdk 컴포넌트 기반)

| 케이스 | 조건 | 기대 응답 |
|---|---|---|
| A (정상) | task-001 JWT → 구독된 task-001 | 200 OK |
| B (Task Misbinding) | task-003 JWT → 구독된 task-001 | 403 Forbidden |
| C (Replay Attack) | 동일 jti 재전송 | 409 Conflict |
| D (만료 토큰) | TTL=0, 1초 후 전송 | 401 Unauthorized |

#### `test_performance.py`
기존 방식 vs 제안 방식 지연시간 비교 (각 100회 반복)

| | 기존 방식 | 제안 방식 |
|---|---|---|
| 평균 | 1.03 ms | 1.13 ms |
| 표준편차 | 0.60 ms | 0.26 ms |
| 오버헤드 | — | +0.10 ms (10.2%) |

---

## 환경 설정

`experiments/.env` 파일:

```env
A2A_PUSH_JWT_SECRET=your-secret-key-here
A2A_PUSH_SUBSCRIBED_TASKS=task-001
```

| 환경변수 | 기본값 | 설명 |
|---|---|---|
| `A2A_PUSH_JWT_SECRET` | **(필수)** | HS256 서명 시크릿 |
| `A2A_PUSH_SUBSCRIBED_TASKS` | `""` (전체 허용) | 허용 task ID 목록 (쉼표 구분) |
| `A2A_PUSH_ISSUER` | `agentB` | JWT `iss` claim |
| `A2A_PUSH_AUDIENCE` | `agentA-webhook` | JWT `aud` claim |
| `A2A_PUSH_TOKEN_TTL` | `60` | JWT 유효 시간(초) |
| `A2A_PUSH_EXPECTED_ISS` | `agentB` | Receiver 기대 `iss` |
| `A2A_PUSH_EXPECTED_AUD` | `agentA-webhook` | Receiver 기대 `aud` |
| `A2A_PUSH_CLOCK_SKEW_SEC` | `30` | 허용 clock skew(초) |
| `A2A_PUSH_JTI_TTL_SEC` | `300` | Anti-replay cache TTL(초) |

---

## 실행 방법

### 통합 흐름 확인

```bash
# 터미널 1: Webhook Receiver
uv run python -m uvicorn webhook_receiver:app --app-dir experiments --host 0.0.0.0 --port 8000

# 터미널 2: Agent Server
uv run python -m uvicorn experiments.run_agent_server:app --host 0.0.0.0 --port 9999

# 터미널 3: 클라이언트
uv run python experiments/test_client_send.py
```

### 보안 케이스 검증

```bash
# Webhook Receiver 실행 후
uv run python experiments/test_security_cases.py
```

### 성능 측정

```bash
# Webhook Receiver 실행 후
uv run python experiments/test_performance.py
```

---

## 기존 SDK와의 차이

| | `BasePushNotificationSender` (기존) | `SecurePushNotificationSender` (제안) |
|---|---|---|
| 인증 방식 | `X-A2A-Notification-Token` (선택적 문자열) | `Authorization: Bearer <JWT>` |
| 발신자 검증 | ❌ | ✅ `iss` claim |
| 태스크 바인딩 | ❌ | ✅ `task_id` claim |
| 만료 검증 | ❌ | ✅ `exp` claim |
| Replay 방지 | ❌ | ✅ `jti` cache |
| 명세 13.2절 충족 | ❌ | ✅ |
