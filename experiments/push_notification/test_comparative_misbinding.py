"""
논문 §5.2 — 4가지 방어 방식 × Task Misbinding 공격 비교

공통 공격 벡터: task-003용 유효 JWT + task-003 페이로드를 각 방식에 전송.
  (공격자는 task-003을 위해 합법적으로 발급받은 JWT를 보유한다고 가정.)

방식 (1): 인증 없음                        → /webhook-plain      → 200 OK   (취약)
방식 (2): 단순 고정 토큰                    → /webhook-token      → 200 OK   (취약)
방식 (3): JWT 서명 검증 (task_id 바인딩 없음) → /webhook-jwt-notask → 200 OK  (취약)
방식 (4): 제안 방식 (JWT + task_id 바인딩)   → /webhook           → 403 Forbidden (방어)

방식 (3)의 취약점:
  JWT 서명을 검증해도, 수신 측이 JWT.task_id를 구독 목록과 대조하지 않으면
  task-003 JWT로 task-003 push를 구독하지 않은 수신자에게 주입 가능.
  → "서명만으로는 Task Misbinding을 막을 수 없다"

실행 방법:
  1. 환경변수 설정 (.env 또는 shell):
     A2A_PUSH_JWT_SECRET=your-secret
     A2A_PUSH_SUBSCRIBED_TASKS=task-001   ← 필수: 미설정 시 방식 (4) 방어 불가

  2. webhook_receiver 서버 실행 (포트 8000):
     uv run python -m uvicorn webhook_receiver:app --app-dir experiments/push_notification --host 0.0.0.0 --port 8000

  3. 실험 실행:
     uv run python -m experiments.push_notification.test_comparative_misbinding
"""

import asyncio
import os

from pathlib import Path

import httpx
from dotenv import load_dotenv

from a2a.server.tasks.inmemory_push_notification_config_store import (
    InMemoryPushNotificationConfigStore,
)
from a2a.server.tasks.secure_push_notification_sender import (
    JWTConfig,
    SecurePushNotificationSender,
)
from a2a.types import PushNotificationConfig

from experiments.push_notification.test_helpers import make_task


load_dotenv(Path(__file__).parent.parent / '.env')

BASE_URL = os.getenv('WEBHOOK_BASE_URL', 'http://127.0.0.1:8000')
SECRET = os.getenv('A2A_PUSH_JWT_SECRET', '')
ISS = os.getenv('A2A_PUSH_ISSUER', 'agentB')
AUD = os.getenv('A2A_PUSH_EXPECTED_AUD', 'agentA-webhook')
FIXED_TOKEN = os.getenv('A2A_PUSH_FIXED_TOKEN', 'demo-fixed-token')

SUBSCRIBED_TASK = 'task-001'  # receiver가 구독한 task
ATTACK_TASK = 'task-003'  # 공격자가 전송할 task (구독 안 됨)


def check(label: str, status: int, expected: int, vulnerable: bool) -> bool:
    ok = status == expected
    vuln_mark = '🔓 취약' if vulnerable else '🛡  방어'
    print(f'{"✅" if ok else "❌"} {vuln_mark}  {label}')
    print(f'   기대={expected}  실측={status}')
    print()
    return ok


async def run() -> None:
    if not SECRET:
        print('❌ A2A_PUSH_JWT_SECRET 환경변수가 없습니다.')
        return

    if 'task-001' not in os.getenv('A2A_PUSH_SUBSCRIBED_TASKS', ''):
        print(
            '❌ A2A_PUSH_SUBSCRIBED_TASKS 환경변수에 task-001이 포함되어야 합니다.\n'
            '   예) export A2A_PUSH_SUBSCRIBED_TASKS=task-001'
        )
        return

    print('=' * 70)
    print('Task Misbinding 공격 — 4가지 방어 방식 비교 실험')
    print(f'공격 시나리오: task_id={ATTACK_TASK!r} → 구독={SUBSCRIBED_TASK!r}')
    print('=' * 70)
    print()

    attack_task = make_task(ATTACK_TASK, text='misbinding attack payload')
    attack_payload = attack_task.model_dump(mode='json', exclude_none=True)

    results = []

    async with httpx.AsyncClient() as client:
        # ── 방식 (1): 인증 없음 ──────────────────────────────────────────
        r = await client.post(f'{BASE_URL}/webhook-plain', json=attack_payload)
        results.append(
            check('방식 (1) 인증 없음                       → /webhook-plain', r.status_code, 200, vulnerable=True)
        )

        # ── 방식 (2): 단순 고정 토큰 ─────────────────────────────────────
        r = await client.post(
            f'{BASE_URL}/webhook-token',
            json=attack_payload,
            headers={'X-A2A-Notification-Token': FIXED_TOKEN},
        )
        results.append(
            check('방식 (2) 단순 고정 토큰                  → /webhook-token', r.status_code, 200, vulnerable=True)
        )

        # 방식 (3)(4) 공통: 공격자가 task-003용 JWT를 합법적으로 보유한다고 가정.
        config_store = InMemoryPushNotificationConfigStore()
        await config_store.set_info(SUBSCRIBED_TASK, PushNotificationConfig(url=f'{BASE_URL}/webhook'))
        sender = SecurePushNotificationSender(
            httpx_client=client,
            config_store=config_store,
            jwt_config=JWTConfig(issuer=ISS, audience=AUD, ttl_seconds=60),
        )
        token_attack = sender._make_jwt(attack_task, f'{BASE_URL}/webhook')  # JWT.task_id=task-003

        # ── 방식 (3): JWT 서명 검증, task_id 바인딩 없음 ─────────────────
        # 수신 측이 JWT 서명만 확인하고 task_id를 구독 목록과 대조하지 않아
        # task-003 JWT → 구독 목록 비교 없음 → 200 OK (취약)
        r = await client.post(
            f'{BASE_URL}/webhook-jwt-notask',
            json=attack_payload,
            headers={'Authorization': f'Bearer {token_attack}'},
        )
        results.append(
            check(
                '방식 (3) JWT 서명만 검증 (task_id 바인딩 없음) → /webhook-jwt-notask',
                r.status_code,
                200,
                vulnerable=True,
            )
        )

        # ── 방식 (4): 제안 방식 — JWT + task_id 서명-시점 바인딩 ──────────
        # 동일 token_attack(task-003 JWT)을 /webhook에 전송.
        # 수신 측이 JWT.task_id=task-003 ∉ SUBSCRIBED_TASKS={task-001} → 403 거부.
        r = await client.post(
            f'{BASE_URL}/webhook',
            json=attack_payload,
            headers={'Authorization': f'Bearer {token_attack}'},
        )
        results.append(
            check('방식 (4) 제안 방식 JWT + task_id 바인딩  → /webhook', r.status_code, 403, vulnerable=False)
        )

    # ── 결과 요약 ────────────────────────────────────────────────────────
    print('=' * 70)
    passed = sum(results)
    print(f'예측 일치: {passed}/4\n')
    print('  방식 (1)(2)(3): Misbinding 성공 → 200 OK  (취약)')
    print('  방식 (4)      : Misbinding 차단 → 403 Forbidden  (방어)')
    print()
    if passed == 4:
        print('✅ 모든 방식이 예측대로 동작 — 논문 주장 실험 검증 완료')
        print('   "서명만으로는 Task Misbinding을 막을 수 없다"  (방식 3 vs 4)')
    else:
        print('❌ 일부 결과가 예측과 다름 — 서버 설정 확인 필요')
    print('=' * 70)


if __name__ == '__main__':
    asyncio.run(run())
