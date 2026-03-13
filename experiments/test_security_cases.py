"""
논문 3.4절 - 공격 시나리오별 방어 검증 테스트
실제 A2A SDK 컴포넌트(SecurePushNotificationSender) 기반

케이스 A: 정상 요청                → 200 OK
케이스 B: Task Misbinding 시도     → 403 Forbidden
케이스 C: Replay Attack            → 409 Conflict
케이스 D: 만료 토큰                → 401 Unauthorized

실행 방법:
  1. webhook_receiver 서버 실행 (포트 8000):
     uv run python -m uvicorn webhook_receiver:app --app-dir experiments --host 0.0.0.0 --port 8000

  2. 테스트 실행:
     uv run python experiments/test_security_cases.py
"""

import asyncio
import os

import httpx

from dotenv import load_dotenv

from a2a.server.tasks.inmemory_push_notification_config_store import (
    InMemoryPushNotificationConfigStore,
)
from a2a.server.tasks.secure_push_notification_sender import (
    SecurePushNotificationSender,
)
from a2a.types import (
    Message,
    Part,
    PushNotificationConfig,
    Role,
    Task,
    TaskState,
    TaskStatus,
    TextPart,
)


load_dotenv()

WEBHOOK_URL = os.getenv('WEBHOOK_URL', 'http://127.0.0.1:8000/webhook')
ISS = os.getenv('A2A_PUSH_ISSUER', 'agentB')
AUD = os.getenv('A2A_PUSH_EXPECTED_AUD', 'agentA-webhook')

SUBSCRIBED_TASK_ID = 'task-001'
OTHER_TASK_ID = 'task-003'


def make_task(task_id: str) -> Task:
    """실제 A2A Task 객체 생성 (에이전트 실행 결과와 동일한 구조)."""
    msg = Message(
        message_id='msg-test',
        role=Role.agent,
        parts=[Part(root=TextPart(text='test payload'))],
        task_id=task_id,
        context_id='ctx-test',
    )
    return Task(
        id=task_id,
        context_id='ctx-test',
        status=TaskStatus(state=TaskState.completed, message=msg),
    )


def make_sender(
    client: httpx.AsyncClient,
    config_store: InMemoryPushNotificationConfigStore,
    ttl: int = 60,
) -> SecurePushNotificationSender:
    """실제 SecurePushNotificationSender 인스턴스 생성."""
    return SecurePushNotificationSender(
        httpx_client=client,
        config_store=config_store,
        issuer=ISS,
        audience=AUD,
        ttl_seconds=ttl,
    )


def check(label: str, status: int, expected: int) -> bool:
    ok = status == expected
    mark = '✅' if ok else '❌'
    print(f'{mark} {label}')
    print(f'   expected={expected}  actual={status}')
    print()
    return ok


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
        config_store = InMemoryPushNotificationConfigStore()
        await config_store.set_info(
            SUBSCRIBED_TASK_ID,
            PushNotificationConfig(url=WEBHOOK_URL),
        )
        sender = make_sender(client, config_store)

        # ── 케이스 A: 정상 요청 ──────────────────────────────
        # SecurePushNotificationSender가 task-001 JWT를 생성하고 전송
        task_a = make_task(SUBSCRIBED_TASK_ID)
        token_a = sender._make_jwt(task_a)
        r = await client.post(
            WEBHOOK_URL,
            json=task_a.model_dump(mode='json', exclude_none=True),
            headers={'Authorization': f'Bearer {token_a}'},
        )
        results.append(
            check('Case A: 정상 요청 (task-001 JWT)', r.status_code, 200)
        )

        # ── 케이스 B: Task Misbinding ─────────────────────────
        # SecurePushNotificationSender가 task-003 JWT를 생성
        # webhook은 task-001만 구독 → task-003은 거부되어야 함
        task_b = make_task(OTHER_TASK_ID)
        token_b = sender._make_jwt(task_b)
        r = await client.post(
            WEBHOOK_URL,
            json=task_b.model_dump(mode='json', exclude_none=True),
            headers={'Authorization': f'Bearer {token_b}'},
        )
        results.append(
            check(
                f'Case B: Task Misbinding (JWT task_id={OTHER_TASK_ID}, 구독={SUBSCRIBED_TASK_ID})',
                r.status_code,
                403,
            )
        )

        # ── 케이스 C: Replay Attack ───────────────────────────
        # 1. 정상 push 전송 (JWT 캡처)
        task_c = make_task(SUBSCRIBED_TASK_ID)
        token_c = sender._make_jwt(task_c)
        await client.post(
            WEBHOOK_URL,
            json=task_c.model_dump(mode='json', exclude_none=True),
            headers={'Authorization': f'Bearer {token_c}'},
        )
        # 2. 캡처한 동일 JWT 재전송 (replay)
        r = await client.post(
            WEBHOOK_URL,
            json=task_c.model_dump(mode='json', exclude_none=True),
            headers={'Authorization': f'Bearer {token_c}'},
        )
        results.append(
            check('Case C: Replay Attack (동일 jti 재전송)', r.status_code, 409)
        )

        # ── 케이스 D: 만료 토큰 ──────────────────────────────
        # TTL=0으로 설정된 SecurePushNotificationSender 사용
        sender_expired = make_sender(client, config_store, ttl=0)
        task_d = make_task(SUBSCRIBED_TASK_ID)
        token_d = sender_expired._make_jwt(task_d)
        await asyncio.sleep(1)  # 만료 대기
        r = await client.post(
            WEBHOOK_URL,
            json=task_d.model_dump(mode='json', exclude_none=True),
            headers={'Authorization': f'Bearer {token_d}'},
        )
        results.append(check('Case D: 만료 토큰 (TTL=0)', r.status_code, 401))

    # ── 결과 요약 ─────────────────────────────────────────
    print('=' * 60)
    passed = sum(results)
    total = len(results)
    print(f'결과: {passed}/{total} 통과')
    print('✅ 모든 케이스 통과' if passed == total else '❌ 일부 케이스 실패')
    print('=' * 60)


if __name__ == '__main__':
    asyncio.run(run())
