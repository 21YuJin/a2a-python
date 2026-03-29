# A2A Push Notification 보안 실험

A2A Python SDK의 Push Notification 경로에서 발생하는 **Task Misbinding** 위협을 분석하고,
JWT 기반 서명-시점 바인딩 방어 방안을 구현·검증하는 실험 코드입니다.

> 본 실험은 석사 숏페이퍼 "A2A Push Notification에서 Task Misbinding 위협 분석 및 JWT 기반 서명-시점 바인딩 방어 방안"의 재현 가능한 구현입니다.

---

## 연구 배경

A2A v1.0 명세 §13.2는 수신 에이전트의 `task_id` 검증을 **권고(SHOULD)**하지만, 특정 인증 방식을 강제하지 않습니다. 이는 다양한 에이전트 간 상호운용성을 보장하기 위한 의도적 설계 결정입니다. 그 결과 공식 Python SDK(`BasePushNotificationSender`)는 기본적으로 `task_id` 바인딩 없이 push를 전송하며, 수신 측도 임의 태스크의 알림을 수락할 수 있는 **Task Misbinding** 취약점이 발생합니다.

본 실험은 이 명세 공백을 채우는 레퍼런스 구현을 제시하고, 4가지 방어 수준의 비교 실험을 통해 "수신자가 JWT의 `task_id`를 구독 목록과 대조하지 않으면 JWT 서명만으로는 Task Misbinding을 방지할 수 없으며, 서명-시점 바인딩과 수신자 측 구독 검증이 함께 갖춰져야 한다"는 것을 실험적으로 검증합니다.

---

## 전체 구조

```
test_client_send.py
    └─► Agent Server (port 9999)          run_agent_server.py
              └─► SecurePushNotificationSender
                        └─► Webhook Receiver (port 8000)    secure_webhook_receiver.py
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

### 실험 스크립트 (experiments/push_notification/)

#### `secure_webhook_receiver.py`
JWT를 검증하는 FastAPI 기반 webhook 수신 서버 (port 8000)

검증 로직은 `SecureWebhookReceiver` 클래스에 캡슐화되어 있으며, `ReceiverConfig` dataclass로 설정을 주입합니다.

```python
@dataclass
class ReceiverConfig:
    signing_key_env: str = 'A2A_PUSH_JWT_SECRET'
    expected_iss: str    = 'agentB'
    expected_aud: str    = 'agentA-webhook'
    alg: str             = 'HS256'
    clock_skew_sec: int  = 30
    jti_ttl_sec: int     = 300
```

| 엔드포인트 | 설명 | 방어 수준 |
|---|---|:---:|
| `POST /webhook-plain` | 인증 없이 수락 | 방식 (1) |
| `POST /webhook-token` | 고정 토큰 확인, task_id 바인딩 없음 | 방식 (2) |
| `POST /webhook-jwt-notask` | JWT 서명 검증, task_id 바인딩 없음 | 방식 (3) |
| `POST /webhook` | JWT + task_id 서명-시점 바인딩 **(제안 방식)** | 방식 (4) |
| `GET /health` | 서버 상태 및 구독 목록 확인 | — |

`/webhook` (제안 방식) 검증 흐름 (`SecureWebhookReceiver.verify()`):
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

> **필수 환경변수:** `A2A_PUSH_SUBSCRIBED_TASKS=task-001` 미설정 시 스크립트가 에러 메시지를 출력하고 조기 종료합니다.

#### `test_security_cases.py`
제안 방식(`/webhook`)에 대한 5가지 공격 시나리오 검증

| 케이스 | 시나리오 | 기대 응답 | 대응 단계 |
|:---:|:---|:---:|:---:|
| A (정상) | task-001 JWT + task-001 페이로드 | 200 OK | — |
| B (Misbinding 변형 1) | task-003 JWT, 구독={task-001} (직접 주입) | 403 Forbidden | ⑤ |
| C (Replay Attack) | 동일 `jti` 재전송 | 409 Conflict | ④ |
| D (만료 토큰) | TTL=0, 1초 후 전송 | 401 Unauthorized | ② |
| E (Misbinding 변형 2) | task-001 JWT + 위조 payload.id=task-003 (JWT 재사용) | 403 Forbidden | ⑥ |

#### `test_helpers.py`
실험 스크립트 간 중복을 제거한 공통 헬퍼 모듈

- `make_task(task_id, text)` — A2A `Task` 객체 생성
- `make_sender(client, webhook_url, task_id, ttl)` — `SecurePushNotificationSender` 인스턴스 생성 (config_store 설정 포함)
- `check(label, response, expected_status, detail_contains)` — HTTP 상태 코드 + 응답 JSON의 `detail` 필드를 함께 검증. `detail_contains`는 선택적이며 None이면 detail 검증을 생략합니다.

`test_security_cases.py`, `test_comparative_misbinding.py`, `test_acceptance_rate.py`의 공통 의존성입니다.

#### `test_performance.py`
기존 방식 vs 제안 방식 지연시간 비교 (N=1000회 반복)

세 가지를 측정합니다:
1. **기존 방식** — `BasePushNotificationSender` → `/webhook-plain` (인증 없음)
2. **제안 방식** — `SecurePushNotificationSender` → `/webhook` (JWT 6단계 검증)
3. **JWT 서명 단독** — HTTP 송수신 없이 `_make_jwt()` 연산만 측정

출력 통계: 평균, 중앙값, 표준편차, **p95**, **p99**, 최소, 최대

측정 결과 (로컬호스트, N=200 기준):

| 방식 | 평균 | 중앙값 | 표준편차 |
|---|---|---|---|
| 기존 (`BasePushNotificationSender`) | 0.92 ms | 0.90 ms | 0.34 ms |
| 제안 (`SecurePushNotificationSender`) | 1.09 ms | 1.07 ms | 0.16 ms |
| **오버헤드** | **+0.17 ms (+18.0%)** | | |

JWT 생성(HMAC-SHA256 + UUID)은 CPU 연산이므로 네트워크 왕복 시간 대비 미미하며,
절대 오버헤드 0.17 ms는 실용적 배포에서 무시 가능한 수준입니다.

#### `test_acceptance_rate.py`  ← **논문 §4.2 정량 검증 실험**
기존 SDK vs 제안 방식에 변형 1·2 공격을 N회 반복 전송하여 **공격 수락률**을 정량 비교합니다.

**실험 설계:**
- 구독 태스크: `task-001`
- 공격 태스크: `task-002`, `task-003`, `task-999` (3종 × `N_REPEAT`회)

| 수신자 구현 | 변형 1 수락률 | 변형 2 수락률 |
|:---|:---:|:---:|
| 기존(인증없음) `/webhook-plain` | **100%** | N/A |
| 기존(JWT서명만) `/webhook-jwt-notask` | **100%** | **100%** |
| 제안(6단계) `/webhook` | **0%** | **0%** |

기대 출력 요약:
```
[ 논문 결론 ]
  기존 SDK 수락률: 변형1=100%  변형2=100%
  제안 방식 수락률: 변형1=0%  변형2=0%

[OK] 기존 100% 수락 / 제안 0% 수락 - 논문 주장 실험 검증 완료
```

> **필수 환경변수:** `A2A_PUSH_JWT_SECRET`, `A2A_PUSH_SUBSCRIBED_TASKS=task-001`

#### `run_agent_server.py`
`SecurePushNotificationSender`를 연동한 HelloWorld 에이전트 서버 (port 9999)

#### `test_client_send.py`
`message/send` JSON-RPC를 호출하는 통합 흐름 확인용 클라이언트

---

### 다이어그램 (experiments/push_notification/)

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
| `A2A_PUSH_JWT_ALG` | `HS256` | JWT 서명 알고리즘 (`secure_webhook_receiver.py` 사용) |
| `WEBHOOK_URL` | `http://127.0.0.1:8000/webhook` | 제안 방식 대상 URL (`test_security_cases.py`, `test_performance.py` 사용) |
| `WEBHOOK_BASE_URL` | `http://127.0.0.1:8000` | Webhook 베이스 URL (`test_comparative_misbinding.py` 사용) |

---

## 실행 방법

### 0. 공통 준비

```bash
# .env 설정 확인
cat experiments/.env

# Webhook Receiver 실행 (모든 실험의 공통 의존성)
uv run python -m uvicorn secure_webhook_receiver:app \
    --app-dir experiments/push_notification --host 0.0.0.0 --port 8000
```

### 1. 핵심 비교 실험 — 4가지 방어 방식 × Misbinding 공격

```bash
# A2A_PUSH_SUBSCRIBED_TASKS=task-001 설정 필수
uv run python -m experiments.push_notification.test_comparative_misbinding
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

  방식 (1)(2)(3): Misbinding 성공 → 200 OK  (취약)
  방식 (4)      : Misbinding 차단 → 403 Forbidden  (방어)

✅ 모든 방식이 예측대로 동작 — 논문 주장 실험 검증 완료
   "서명만으로는 Task Misbinding을 막을 수 없다"  (방식 3 vs 4)
```

### 2. 보안 케이스 5종 검증

```bash
uv run python -m experiments.push_notification.test_security_cases
```

### 3. 공격 수락률 비교 실험 (정량 검증)

```bash
# A2A_PUSH_SUBSCRIBED_TASKS=task-001 설정 필수
uv run python -m experiments.push_notification.test_acceptance_rate
```

### 4. 성능 오버헤드 측정

```bash
uv run python -m experiments.push_notification.test_performance
```

기대 출력 (N=1000, 로컬호스트):
```
[기존 방식 (BasePushNotificationSender)] n=1000
  평균:     0.92 ms
  중앙값:   0.90 ms
  표준편차: 0.34 ms
  p95:      ...
  p99:      ...

[제안 방식 (SecurePushNotificationSender + JWT)] n=1000
  평균:     1.09 ms
  중앙값:   1.07 ms
  표준편차: 0.16 ms

[JWT 서명 단독 (HMAC-SHA256 + UUID 생성)] n=1000
  ...

전체 오버헤드: +0.17 ms / 요청 (18.0%)
```

### 5. 통합 흐름 확인 (에이전트 → Webhook 실제 전송)

```bash
# 터미널 2: Agent Server
uv run python -m uvicorn experiments.push_notification.run_agent_server:app \
    --host 0.0.0.0 --port 9999

# 터미널 3: 클라이언트
uv run python -m experiments.push_notification.test_client_send
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

- Python 3.12.12 / a2a-sdk 0.3.25 / PyJWT 2.x / FastAPI 0.135.1
- OS: Windows 11 Home 10.0.26200
- 실험 설정: HS256, JWT TTL=60초, 구독 목록 `{task-001}`
