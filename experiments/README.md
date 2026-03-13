# A2A Push Notification 보안 실험

A2A Python SDK의 Push Notification 경로에서 발생하는 **Task Misbinding** 위협을 분석하고,
JWT 기반 서명-시점 바인딩 방어 방안을 구현·검증하는 실험 코드입니다.

> 본 실험은 석사 숏페이퍼 "A2A Push Notification에서 Task Misbinding 위협 분석 및 JWT 기반 서명-시점 바인딩 방어 방안"의 재현 가능한 구현입니다.

---

## 연구 배경

A2A v1.0 명세 §13.2는 수신 에이전트의 `task_id` 검증을 **권고(SHOULD)**하지만, 특정 인증 방식을 강제하지 않습니다. 이는 다양한 에이전트 간 상호운용성을 보장하기 위한 의도적 설계 결정입니다. 그 결과 공식 Python SDK(`BasePushNotificationSender`)는 기본적으로 `task_id` 바인딩 없이 push를 전송하며, 수신 측도 임의 태스크의 알림을 수락할 수 있는 **Task Misbinding** 취약점이 발생합니다.

본 실험은 이 명세 공백을 채우는 레퍼런스 구현을 제시하고, 4가지 방어 수준의 비교 실험을 통해 "JWT 서명 단독으로는 Task Misbinding을 방지할 수 없으며, 서명 시점에 `task_id`를 클레임으로 포함하는 바인딩이 필수적"임을 실험적으로 검증합니다.

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

- 알고리즘: HS256 (HMAC-SHA256)
- JWT claims: `iss`, `aud`, `iat`, `exp`, `jti`, **`task_id`** (서명-시점 바인딩 핵심)
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

#### `webhook_receiver.py`
JWT를 검증하는 FastAPI 기반 webhook 수신 서버 (port 8000)

| 엔드포인트 | 설명 | 방어 수준 |
|---|---|:---:|
| `POST /webhook-plain` | 인증 없이 수락 | 방식 (1) |
| `POST /webhook-token` | 고정 토큰 확인, task_id 바인딩 없음 | 방식 (2) |
| `POST /webhook-jwt-notask` | JWT 서명 검증, task_id 바인딩 없음 | 방식 (3) |
| `POST /webhook` | JWT + task_id 서명-시점 바인딩 **(제안 방식)** | 방식 (4) |
| `GET /health` | 서버 상태 및 구독 목록 확인 | — |

`/webhook` (제안 방식) 검증 흐름:
```
POST /webhook
    ├─ ① Authorization: Bearer 헤더 확인
    ├─ ② JWT 서명·만료·필수클레임 검증 (HS256)
    ├─ ③ iat 신선도 검증 (clock skew 허용)
    ├─ ④ jti anti-replay 캐시 확인 → 409 Conflict
    ├─ ⑤ JWT.task_id ∈ 구독 목록 검증 → 403 Forbidden  ← Task Misbinding 방어 핵심
    └─ ⑥ JWT.task_id == payload.id 교차 검증 (TLS 전제) → 403 Forbidden
```

#### `test_comparative_misbinding.py`  ← **논문 핵심 실험**
4가지 방어 방식에 동일한 공격 벡터를 전송하여 방어 효과를 비교합니다.

**공통 공격 벡터:** `task-003` 유효 JWT + `task-003` 페이로드 → 구독 목록 `{task-001}` 수신자

| 방식 | 인증 방법 | 기대 응답 | 판정 |
|:---:|:---|:---:|:---:|
| (1) | 인증 없음 | 200 OK | 취약 |
| (2) | 고정 토큰 (탈취 가정) | 200 OK | 취약 |
| (3) | JWT 서명 (task_id 바인딩 없음) | 200 OK | 취약 |
| (4) | JWT + task_id 서명-시점 바인딩 | **403 Forbidden** | **방어** |

> **필수 환경변수:** `A2A_PUSH_SUBSCRIBED_TASKS=task-001` 미설정 시 방식 (4)도 200을 반환하며 실험이 침묵 실패합니다.

#### `test_security_cases.py`
제안 방식(`/webhook`)에 대한 4가지 공격 시나리오 검증

| 케이스 | 시나리오 | 기대 응답 |
|:---:|:---|:---:|
| A (정상) | task-001 JWT + task-001 페이로드 | 200 OK |
| B (Task Misbinding) | task-003 JWT, 구독={task-001} | 403 Forbidden |
| C (Replay Attack) | 동일 `jti` 재전송 | 409 Conflict |
| D (만료 토큰) | TTL=0, 1초 후 전송 | 401 Unauthorized |

#### `test_performance.py`
기존 방식 vs 제안 방식 지연시간 비교 (N=50회 반복)

JWT 생성(HMAC-SHA256 + UUID)은 CPU 연산이므로 네트워크 왕복 시간 대비 미미하며,
측정된 오버헤드는 요청당 수 ms 이하로 실용적 배포에 무시 가능한 수준입니다.

#### `run_agent_server.py`
`SecurePushNotificationSender`를 연동한 HelloWorld 에이전트 서버 (port 9999)

#### `test_client_send.py`
`message/send` JSON-RPC를 호출하는 통합 흐름 확인용 클라이언트

---

### 다이어그램 (experiments/)

| 파일 | 내용 |
|---|---|
| `task_misbinding_diagram.drawio` | Task Misbinding 공격(방식 1~3)과 방어(방식 4) 시나리오 시퀀스 다이어그램 |
| `system_architecture_diagram.drawio` | 클래스 구조(`BasePushNotificationSender` → `SecurePushNotificationSender` 상속) + `/webhook` 6단계 검증 흐름 |

[diagrams.net](https://app.diagrams.net)에서 파일을 열어 확인할 수 있습니다.

---

## 환경 설정

`experiments/.env` 파일:

```env
# 필수
A2A_PUSH_JWT_SECRET=your-secret-key-here

# test_comparative_misbinding.py 실행 시 필수
A2A_PUSH_SUBSCRIBED_TASKS=task-001
```

| 환경변수 | 기본값 | 설명 |
|---|---|---|
| `A2A_PUSH_JWT_SECRET` | **(필수)** | HS256 서명 시크릿 |
| `A2A_PUSH_SUBSCRIBED_TASKS` | `""` (전체 허용) | 허용 task ID 목록 (쉼표 구분). **미설정 시 방식 (4) 방어 불가** |
| `A2A_PUSH_FIXED_TOKEN` | `demo-fixed-token` | 방식 (2) 비교 실험용 고정 토큰 |
| `A2A_PUSH_ISSUER` | `agentB` | JWT `iss` claim |
| `A2A_PUSH_EXPECTED_AUD` | `agentA-webhook` | JWT `aud` claim / Receiver 기대값 |
| `A2A_PUSH_EXPECTED_ISS` | `agentB` | Receiver 기대 `iss` |
| `A2A_PUSH_CLOCK_SKEW_SEC` | `30` | 허용 clock skew(초) |
| `A2A_PUSH_JTI_TTL_SEC` | `300` | Anti-replay cache TTL(초) |

---

## 실행 방법

### 0. 공통 준비

```bash
# .env 설정 확인
cat experiments/.env

# Webhook Receiver 실행 (모든 실험의 공통 의존성)
uv run python -m uvicorn webhook_receiver:app \
    --app-dir experiments --host 0.0.0.0 --port 8000
```

### 1. 핵심 비교 실험 — 4가지 방어 방식 × Misbinding 공격

```bash
# A2A_PUSH_SUBSCRIBED_TASKS=task-001 설정 필수
uv run python experiments/test_comparative_misbinding.py
```

기대 출력:
```
======================================================================
Task Misbinding 공격 — 4가지 방어 방식 비교 실험
공격 시나리오: task_id='task-003' → 구독='task-001'
======================================================================

✅ 🔓 취약  방식 (1) 인증 없음                       → /webhook-plain
   기대=200  실측=200

✅ 🔓 취약  방식 (2) 단순 고정 토큰                  → /webhook-token
   기대=200  실측=200

✅ 🔓 취약  방식 (3) JWT 서명만 검증 (task_id 바인딩 없음) → /webhook-jwt-notask
   기대=200  실측=200

✅ 🛡  방어  방식 (4) 제안 방식 JWT + task_id 바인딩  → /webhook
   기대=403  실측=403

예측 일치: 4/4
✅ 모든 방식이 예측대로 동작 — 논문 주장 실험 검증 완료
   "서명만으로는 Task Misbinding을 막을 수 없다"  (방식 3 vs 4)
```

### 2. 보안 케이스 4종 검증

```bash
uv run python experiments/test_security_cases.py
```

### 3. 성능 오버헤드 측정

```bash
uv run python experiments/test_performance.py
```

### 4. 통합 흐름 확인 (에이전트 → Webhook 실제 전송)

```bash
# 터미널 2: Agent Server
uv run python -m uvicorn experiments.run_agent_server:app \
    --host 0.0.0.0 --port 9999

# 터미널 3: 클라이언트
uv run python experiments/test_client_send.py
```

---

## 기존 SDK와의 차이

| | `BasePushNotificationSender` (기존) | `SecurePushNotificationSender` (제안) |
|---|---|---|
| 인증 방식 | `X-A2A-Notification-Token` (선택적) | `Authorization: Bearer <JWT>` |
| 발신자 검증 | ❌ | ✅ `iss` claim |
| **태스크 바인딩** | ❌ | ✅ **`task_id` claim (서명-시점 바인딩)** |
| 만료 검증 | ❌ | ✅ `exp` claim |
| Replay 방지 | ❌ | ✅ `jti` cache |
| 페이로드 교차 검증 | ❌ | ✅ `JWT.task_id == payload.id` (TLS 전제) |
| A2A 명세 §13.2 충족 | ❌ | ✅ |

---

## 알려진 한계

| 한계 | 내용 | 대안 |
|:---:|:---|:---|
| H1 | HS256 공유 시크릿 유출 시 전체 보안 붕괴 | RS256/ES256 + JWKS 엔드포인트 |
| H2 | 인메모리 `jti` 캐시 — 수평 확장 불가 | Redis 등 공유 분산 저장소 |
| H3 | 단일 프로세스 시뮬레이션 — 실제 네트워크 공격 미재현 | 분리된 네트워크 환경 재실험 |
| H4 | 교차 검증(⑥)은 TLS 없이 MITM으로 우회 가능 | TLS 전제 명시 또는 페이로드 서명 |
| H5 | a2a-sdk v0.3.25 기반 — 명세 변경 시 재검토 필요 | 최신 SDK 버전 추적 |

---

## 실험 환경

- Python 3.12.12 / a2a-sdk v0.3.25 / PyJWT 2.x / FastAPI
- OS: Windows 11 Home 10.0.26200
- 실험 설정: HS256, TTL=60초, `A2A_PUSH_SUBSCRIBED_TASKS=task-001`
