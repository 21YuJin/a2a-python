"""
성능 측정 - 기존 방식 vs 제안 방식 지연시간 비교

기존 방식: BasePushNotificationSender → /webhook-plain (토큰 없음)
제안 방식: SecurePushNotificationSender → /webhook (JWT 검증)

실행 방법:
  1. secure_webhook_receiver 서버 실행:
     uv run python -m uvicorn secure_webhook_receiver:app --app-dir experiments/push_notification --host 0.0.0.0 --port 8000

  2. 측정 실행:
     uv run python -m experiments.push_notification.test_performance
"""

import asyncio
import os
import statistics
import time

from pathlib import Path

import httpx

from dotenv import load_dotenv

from a2a.server.tasks.base_push_notification_sender import (
    BasePushNotificationSender,
)
from a2a.server.tasks.inmemory_push_notification_config_store import (
    InMemoryPushNotificationConfigStore,
)
from a2a.server.tasks.secure_push_notification_sender import (
    JWTConfig,
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


load_dotenv(Path(__file__).parent.parent / '.env')

WEBHOOK_URL = os.getenv('WEBHOOK_URL', 'http://127.0.0.1:8000/webhook')
WEBHOOK_PLAIN_URL = 'http://127.0.0.1:8000/webhook-plain'
ISS = os.getenv('A2A_PUSH_ISSUER', 'agentB')
AUD = os.getenv('A2A_PUSH_EXPECTED_AUD', 'agentA-webhook')
TASK_ID = 'task-001'
REPEAT = 200


def make_task(task_id: str) -> Task:
    msg = Message(
        message_id='msg-perf',
        role=Role.agent,
        parts=[Part(root=TextPart(text='performance test'))],
        task_id=task_id,
        context_id='ctx-perf',
    )
    return Task(
        id=task_id,
        context_id='ctx-perf',
        status=TaskStatus(state=TaskState.completed, message=msg),
    )


def stats(label: str, times: list[float]) -> None:
    ms = [t * 1000 for t in times]
    print(f'\n[{label}] n={len(ms)}')
    print(f'  평균:   {statistics.mean(ms):.2f} ms')
    print(f'  중앙값: {statistics.median(ms):.2f} ms')
    print(f'  최소:   {min(ms):.2f} ms')
    print(f'  최대:   {max(ms):.2f} ms')
    print(f'  표준편차: {statistics.stdev(ms):.2f} ms')


async def measure_plain(client: httpx.AsyncClient) -> list[float]:
    """기존 방식: BasePushNotificationSender (토큰 없음)."""
    config_store = InMemoryPushNotificationConfigStore()
    await config_store.set_info(
        TASK_ID, PushNotificationConfig(url=WEBHOOK_PLAIN_URL)
    )
    sender = BasePushNotificationSender(
        httpx_client=client,
        config_store=config_store,
    )
    task = make_task(TASK_ID)
    times = []
    for _ in range(REPEAT):
        start = time.perf_counter()
        await sender.send_notification(task)
        times.append(time.perf_counter() - start)
    return times


async def measure_secure(client: httpx.AsyncClient) -> list[float]:
    """제안 방식: SecurePushNotificationSender (JWT 검증)."""
    config_store = InMemoryPushNotificationConfigStore()
    await config_store.set_info(
        TASK_ID, PushNotificationConfig(url=WEBHOOK_URL)
    )
    sender = SecurePushNotificationSender(
        httpx_client=client,
        config_store=config_store,
        jwt_config=JWTConfig(issuer=ISS, audience=AUD, ttl_seconds=60),
    )
    times = []
    for _ in range(REPEAT):
        # 매 요청마다 새 Task 객체 생성 → SecurePushNotificationSender가 새 jti UUID 생성
        start = time.perf_counter()
        await sender.send_notification(make_task(TASK_ID))
        times.append(time.perf_counter() - start)
    return times


async def run() -> None:
    if not os.getenv('A2A_PUSH_JWT_SECRET'):
        print('❌ A2A_PUSH_JWT_SECRET 환경변수가 없습니다.')
        return

    print('=' * 55)
    print(f'성능 측정: 각 방식 {REPEAT}회 반복')
    print(f'기존 방식 대상: {WEBHOOK_PLAIN_URL}')
    print(f'제안 방식 대상: {WEBHOOK_URL}')
    print('=' * 55)

    async with httpx.AsyncClient() as client:
        print('\n기존 방식 측정 중...')
        plain_times = await measure_plain(client)

        print('제안 방식 측정 중...')
        secure_times = await measure_secure(client)

    stats('기존 방식 (BasePushNotificationSender)', plain_times)
    stats('제안 방식 (SecurePushNotificationSender + JWT)', secure_times)

    plain_avg = statistics.mean(plain_times) * 1000
    secure_avg = statistics.mean(secure_times) * 1000
    overhead = secure_avg - plain_avg

    print(
        f'\n오버헤드: +{overhead:.2f} ms / 요청 ({overhead / plain_avg * 100:.1f}%)'
    )
    print('=' * 55)


if __name__ == '__main__':
    asyncio.run(run())
