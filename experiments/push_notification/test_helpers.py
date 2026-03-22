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


def check(
    label: str,
    response: 'httpx.Response',
    expected_status: int,
    detail_contains: str | None = None,
) -> bool:
    """HTTP 상태 코드와 오류 메시지(detail 필드)를 함께 검증한다.

    Args:
        label:           케이스 설명.
        response:        httpx 응답 객체.
        expected_status: 기대 HTTP 상태 코드.
        detail_contains: 응답 JSON의 ``detail`` 필드에 포함되어야 할 문자열.
                         None이면 detail 검증을 생략한다.
    """
    status_ok = response.status_code == expected_status
    actual_detail = ''
    detail_ok = True
    if detail_contains is not None and status_ok:
        try:
            actual_detail = response.json().get('detail', '')
        except Exception:
            actual_detail = ''
        detail_ok = detail_contains.lower() in actual_detail.lower()

    ok = status_ok and detail_ok
    print(f'{"✅" if ok else "❌"} {label}')
    print(f'   HTTP {response.status_code} (expected {expected_status})')
    if detail_contains is not None:
        match = '✓' if detail_ok else '✗'
        print(f'   detail [{match}]: "{actual_detail}" (expected ~"{detail_contains}")')
    print()
    return ok
