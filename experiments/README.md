# A2A Secure Push Notification Experiment

이 디렉토리는 A2A Python SDK에 **JWT 기반 Secure Push Notification**을 구현하고 검증하는 실험 코드입니다.

---

## 개요

기존 A2A SDK의 `BasePushNotificationSender`는 단순 HTTP POST만 지원합니다.
이 실험은 **HS256 JWT**를 이용해 push notification 요청을 서명하고, 수신 측에서 검증하는 end-to-end 흐름을 구현합니다.

```
Test Client ──► Agent Server (port 9999) ──► Webhook Receiver (port 8000)
                    │                              │
              SecurePushSender              JWT 검증 + 재전송 방지
              (JWT 서명 후 POST)           (HS256, exp, jti cache)
```

---

## 추가/수정한 파일

### `src/a2a/server/tasks/secure_push_notification_sender.py` (신규)

`BasePushNotificationSender`를 상속해 push 전송 시 JWT를 자동 첨부합니다.

- **알고리즘**: HS256
- **JWT claims**: `iss`, `aud`, `iat`, `exp`, `jti`, `task_id`
- **시크릿**: 환경변수 `A2A_PUSH_JWT_SECRET`에서 로드

```python
push_sender = SecurePushNotificationSender(
    httpx_client=http_client,
    config_store=push_config_store,
    issuer='agentB',
    audience='agentA-webhook',
    ttl_seconds=60,
)
```

### `experiments/run_agent_server.py` (신규)

`SecurePushNotificationSender`를 연동한 HelloWorld 에이전트 서버입니다.

- 포트: `9999`
- 에이전트 실행 흐름:
  1. `TaskStatusUpdateEvent(working)` 발행 → Task 생성
  2. `Message("Hello World")` 발행
  3. `TaskStatusUpdateEvent(completed, final=True)` 발행 → push notification 2회 전송

### `experiments/webhook_receiver.py` (신규)

JWT를 검증하는 FastAPI 기반 webhook 수신 서버입니다.

- 포트: `8000`
- 검증 항목:
  - `Authorization: Bearer <JWT>` 헤더 필수
  - HS256 서명 검증 (`verify_signature`)
  - `exp`, `iat`, `jti` claim 필수 검증
  - `iat` freshness 검사 (clock skew 허용)
  - **Anti-replay**: `jti` 중복 수신 차단 (in-memory cache)
  - task_id 바인딩 검사 (환경변수로 허용 목록 설정)

### `experiments/test_client_send.py` (신규)

`message/send` JSON-RPC를 호출하는 테스트 클라이언트입니다.

- `blocking: false`로 요청 → 서버가 즉시 `working` 상태 반환
- `push_notification_config`에 webhook URL 등록
- 이후 백그라운드에서 에이전트 완료 시 webhook으로 push 전송

---

## 환경 설정

`experiments/.env` 파일을 생성합니다:

```env
A2A_PUSH_JWT_SECRET=your-secret-key-here
```

| 환경변수 | 기본값 | 설명 |
|---------|--------|------|
| `A2A_PUSH_JWT_SECRET` | (필수) | HS256 서명 시크릿 |
| `A2A_PUSH_ISSUER` | `agentB` | JWT `iss` claim |
| `A2A_PUSH_AUDIENCE` | `agentA-webhook` | JWT `aud` claim |
| `A2A_PUSH_TOKEN_TTL` | `60` | JWT 유효 시간(초) |
| `A2A_PUSH_EXPECTED_ISS` | `agentB` | Receiver가 기대하는 `iss` |
| `A2A_PUSH_EXPECTED_AUD` | `agentA-webhook` | Receiver가 기대하는 `aud` |
| `A2A_PUSH_CLOCK_SKEW_SEC` | `30` | 허용 clock skew(초) |
| `A2A_PUSH_JTI_TTL_SEC` | `300` | Anti-replay cache TTL(초) |
| `A2A_PUSH_SUBSCRIBED_TASKS` | `""` (전체 허용) | 허용할 task ID 목록 (쉼표 구분) |

---

## 실행 방법

### 1. Webhook Receiver 시작

```bash
uv run python -m uvicorn webhook_receiver:app --app-dir experiments --host 0.0.0.0 --port 8000
```

### 2. Agent Server 시작

```bash
uv run python -m uvicorn experiments.run_agent_server:app --host 0.0.0.0 --port 9999
```

### 3. 테스트 클라이언트 실행

```bash
uv run python experiments/test_client_send.py
```

---

## 정상 동작 로그

**Agent Server (port 9999)**
```
INFO:a2a.server.tasks.task_manager:Task not found ... Creating new task for event (task_id: <uuid>)
INFO:httpx:HTTP Request: POST http://127.0.0.1:8000/webhook "HTTP/1.1 200 OK"
INFO:httpx:HTTP Request: POST http://127.0.0.1:8000/webhook "HTTP/1.1 200 OK"
INFO:a2a.server.tasks.secure_push_notification_sender:Secure push sent task_id=<uuid> to http://127.0.0.1:8000/webhook status=200
INFO:a2a.server.tasks.secure_push_notification_sender:Secure push sent task_id=<uuid> to http://127.0.0.1:8000/webhook status=200
```

**Webhook Receiver (port 8000)**
```
INFO:webhook_receiver:✅ Accepted webhook: iss=agentB aud=agentA-webhook task_id=<uuid> jti=<uuid> payload_keys=[...]
INFO:     127.0.0.1:XXXXX - "POST /webhook HTTP/1.1" 200 OK
INFO:webhook_receiver:✅ Accepted webhook: iss=agentB aud=agentA-webhook task_id=<uuid> jti=<uuid> payload_keys=[...]
INFO:     127.0.0.1:XXXXX - "POST /webhook HTTP/1.1" 200 OK
```

> Push notification이 2회 전송되는 이유: `Message` 이벤트와 `TaskStatusUpdateEvent(completed)` 이벤트 처리 후 각각 1회씩 발송됩니다.

---

## 핵심 구현 포인트

### Push Notification이 non-blocking에서만 동작하는 이유

A2A SDK의 `ResultAggregator.consume_and_break_on_interrupt`는 `event_callback`(push notification)을
`_continue_consuming` 백그라운드 태스크에서만 호출합니다.
`blocking=true`이면 이 백그라운드 태스크가 생성되지 않아 push notification이 전송되지 않습니다.

```
blocking=false → 첫 이벤트 처리 후 즉시 응답 반환
              → 나머지 이벤트는 _continue_consuming(백그라운드)에서 처리
              → 각 이벤트마다 event_callback() 호출 → push notification 전송
```

### Anti-replay (jti cache)

동일한 JWT를 재사용한 공격을 막기 위해 `jti`를 in-memory dict에 저장합니다.
TTL(`JTI_TTL_SEC`) 이후 자동 만료됩니다.
