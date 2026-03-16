"""
논문 §5.3 — 공격 시나리오별 방어 검증 테스트
실제 A2A SDK 컴포넌트(SecurePushNotificationSender) 기반

케이스 A: 정상 요청                       → 200 OK
케이스 B: Task Misbinding (변형 1: 직접 주입)  → 403 Forbidden
케이스 C: Replay Attack                   → 409 Conflict
케이스 D: 만료 토큰                        → 401 Unauthorized
케이스 E: Task Misbinding (변형 2: JWT 재사용) → 403 Forbidden

실행 방법:
  1. webhook_receiver 서버 실행 (포트 8000):
     uv run python -m uvicorn webhook_receiver:app --app-dir experiments/push_notification --host 0.0.0.0 --port 8000

  2. 테스트 실행:
     uv run python -m experiments.push_notification.test_security_cases
"""

import asyncio
import os

from pathlib import Path

import httpx
from dotenv import load_dotenv

from experiments.push_notification.test_helpers import check, make_sender, make_task


load_dotenv(Path(__file__).parent.parent / '.env')

WEBHOOK_URL = os.getenv('WEBHOOK_URL', 'http://127.0.0.1:8000/webhook')

SUBSCRIBED_TASK_ID = 'task-001'
OTHER_TASK_ID = 'task-003'


async def run():
    if not os.getenv('A2A_PUSH_JWT_SECRET'):
        print('❌ A2A_PUSH_JWT_SECRET 환경변수가 없습니다.')
        return

    print('=' * 60)
    print('A2A Push Notification 보안 케이스 검증')
    print(f'대상 webhook: {WEBHOOK_URL}')
    print(f'구독 task: {SUBSCRIBED_TASK_ID}')
    print('=' * 60)
    print()

    results = []

    async with httpx.AsyncClient() as client:
        sender = await make_sender(client, WEBHOOK_URL, SUBSCRIBED_TASK_ID)

        # ── 케이스 A: 정상 요청 ──────────────────────────────
        # task-001 JWT + task-001 페이로드 → 200 OK
        task_a = make_task(SUBSCRIBED_TASK_ID)
        token_a = sender._make_jwt(task_a)
        r = await client.post(
            WEBHOOK_URL,
            json=task_a.model_dump(mode='json', exclude_none=True),
            headers={'Authorization': f'Bearer {token_a}'},
        )
        results.append(check('Case A: 정상 요청 (task-001 JWT + task-001 payload)', r.status_code, 200))

        # ── 케이스 B: Task Misbinding 변형 1 (직접 주입) ─────
        # 공격자가 task-003 JWT를 합법적으로 발급받아 task-001 구독자에게 전송.
        # 수신자의 구독 목록 대조(단계 ⑤)로 차단.
        task_b = make_task(OTHER_TASK_ID)
        token_b = sender._make_jwt(task_b)
        r = await client.post(
            WEBHOOK_URL,
            json=task_b.model_dump(mode='json', exclude_none=True),
            headers={'Authorization': f'Bearer {token_b}'},
        )
        results.append(
            check(
                f'Case B: Misbinding 변형 1 — JWT.task_id={OTHER_TASK_ID}, 구독={SUBSCRIBED_TASK_ID}',
                r.status_code,
                403,
            )
        )

        # ── 케이스 C: Replay Attack ───────────────────────────
        # 정상 JWT를 캡처 후 동일 jti로 재전송 → jti 캐시(단계 ④)로 차단.
        task_c = make_task(SUBSCRIBED_TASK_ID)
        token_c = sender._make_jwt(task_c)
        await client.post(
            WEBHOOK_URL,
            json=task_c.model_dump(mode='json', exclude_none=True),
            headers={'Authorization': f'Bearer {token_c}'},
        )
        r = await client.post(
            WEBHOOK_URL,
            json=task_c.model_dump(mode='json', exclude_none=True),
            headers={'Authorization': f'Bearer {token_c}'},
        )
        results.append(check('Case C: Replay Attack (동일 jti 재전송)', r.status_code, 409))

        # ── 케이스 D: 만료 토큰 ──────────────────────────────
        # TTL=0으로 발급된 JWT를 1초 후 전송 → exp 검증(단계 ②)으로 차단.
        sender_expired = await make_sender(client, WEBHOOK_URL, SUBSCRIBED_TASK_ID, ttl=0)
        task_d = make_task(SUBSCRIBED_TASK_ID)
        token_d = sender_expired._make_jwt(task_d)
        await asyncio.sleep(1)
        r = await client.post(
            WEBHOOK_URL,
            json=task_d.model_dump(mode='json', exclude_none=True),
            headers={'Authorization': f'Bearer {token_d}'},
        )
        results.append(check('Case D: 만료 토큰 (TTL=0, 1초 후 전송)', r.status_code, 401))

        # ── 케이스 E: Task Misbinding 변형 2 (JWT 재사용) ─────
        # 공격자가 task-001의 유효 JWT를 탈취한 뒤,
        # task-001 JWT는 그대로 두고 페이로드의 id만 task-003으로 위조하여 전송.
        # JWT.task_id(task-001) ≠ payload.id(task-003) → 교차 검증(단계 ⑥)으로 차단.
        task_e_legit = make_task(SUBSCRIBED_TASK_ID)
        token_e = sender._make_jwt(task_e_legit)  # 합법 JWT: task_id=task-001
        forged_payload = make_task(OTHER_TASK_ID).model_dump(mode='json', exclude_none=True)  # 위조 payload: id=task-003
        r = await client.post(
            WEBHOOK_URL,
            json=forged_payload,
            headers={'Authorization': f'Bearer {token_e}'},
        )
        results.append(
            check(
                f'Case E: Misbinding 변형 2 — JWT.task_id={SUBSCRIBED_TASK_ID}, payload.id={OTHER_TASK_ID}',
                r.status_code,
                403,
            )
        )

    # ── 결과 요약 ─────────────────────────────────────────
    print('=' * 60)
    passed = sum(results)
    total = len(results)
    print(f'결과: {passed}/{total} 통과')
    print('✅ 모든 케이스 통과' if passed == total else '❌ 일부 케이스 실패')
    print('=' * 60)


if __name__ == '__main__':
    asyncio.run(run())
