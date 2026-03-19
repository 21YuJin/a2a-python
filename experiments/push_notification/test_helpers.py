"""공통 테스트 헬퍼 — 실험 스크립트 간 중복 제거."""

import os

import httpx

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


def make_task(task_id: str, text: str = 'test payload') -> Task:
    """A2A Task 객체 생성."""
    msg = Message(
        message_id='msg-test',
        role=Role.agent,
        parts=[Part(root=TextPart(text=text))],
        task_id=task_id,
        context_id='ctx-test',
    )
    return Task(
        id=task_id,
        context_id='ctx-test',
        status=TaskStatus(state=TaskState.completed, message=msg),
    )


async def make_sender(
    client: httpx.AsyncClient,
    webhook_url: str,
    task_id: str,
    ttl: int = 60,
) -> SecurePushNotificationSender:
    """config_store 설정 포함 SecurePushNotificationSender 생성."""
    config_store = InMemoryPushNotificationConfigStore()
    await config_store.set_info(task_id, PushNotificationConfig(url=webhook_url))
    return SecurePushNotificationSender(
        httpx_client=client,
        config_store=config_store,
        jwt_config=JWTConfig(
            issuer=os.getenv('A2A_PUSH_ISSUER', 'agentB'),
            audience=os.getenv('A2A_PUSH_EXPECTED_AUD', 'agentA-webhook'),
            ttl_seconds=ttl,
        ),
    )


def check(label: str, status: int, expected: int) -> bool:
    ok = status == expected
    print(f'{"✅" if ok else "❌"} {label}')
    print(f'   expected={expected}  actual={status}')
    print()
    return ok
