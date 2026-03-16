import datetime as dt
import logging
import os
import uuid

import httpx

from dotenv import load_dotenv

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.apps.jsonrpc.fastapi_app import A2AFastAPIApplication
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks.inmemory_push_notification_config_store import (
    InMemoryPushNotificationConfigStore,
)
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.server.tasks.secure_push_notification_sender import (
    SecurePushNotificationSender,
)
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
    Message,
    Part,
    Role,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
    TextPart,
)


from pathlib import Path
load_dotenv(Path(__file__).parent.parent / ".env")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('run_agent_server')


def _make_message(text: str, *, task_id: str, context_id: str) -> Message:
    return Message(
        message_id=str(uuid.uuid4()),
        role=Role.agent,
        parts=[Part(root=TextPart(text=text))],
        task_id=task_id,
        context_id=context_id,
    )


def _make_status(state: TaskState, msg: Message) -> TaskStatus:
    # 네 버전 필드 확정: message, state, timestamp
    return TaskStatus(
        state=state,
        message=msg,
        timestamp=dt.datetime.now(dt.timezone.utc).isoformat(),
    )


def _make_status_event(
    task_id: str, context_id: str, status: TaskStatus, final: bool
) -> TaskStatusUpdateEvent:
    # 네 버전 필드 확정: task_id, context_id, status, final (+kind/metadata는 optional)
    return TaskStatusUpdateEvent(
        task_id=task_id,
        context_id=context_id,
        status=status,
        final=final,
    )


class HelloWorldExecutor(AgentExecutor):
    async def execute(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        # context의 task_id/context_id는 Optional일 수 있어서 보장해줌
        task_id = context.task_id or str(uuid.uuid4())
        context_id = context.context_id or str(uuid.uuid4())

        # (1) WORKING 상태 이벤트 -> Task 생성/업데이트 트리거
        working_msg = _make_message(
            'Working...', task_id=task_id, context_id=context_id
        )
        working_status = _make_status(TaskState.working, working_msg)
        await event_queue.enqueue_event(
            _make_status_event(task_id, context_id, working_status, final=False)
        )

        # (2) 실제 응답 메시지
        hello_msg = _make_message(
            'Hello World', task_id=task_id, context_id=context_id
        )
        await event_queue.enqueue_event(hello_msg)

        # (3) COMPLETED 상태 이벤트 -> 최종 상태 트리거
        done_msg = _make_message(
            'Completed', task_id=task_id, context_id=context_id
        )
        done_status = _make_status(TaskState.completed, done_msg)
        await event_queue.enqueue_event(
            _make_status_event(task_id, context_id, done_status, final=True)
        )

    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        return


def build_agent_card() -> AgentCard:
    return AgentCard(
        protocol_version='0.3.0',
        name='A2A Python Local Agent',
        description='Local agent server for webhook push security experiments',
        url='http://localhost:9999/',
        preferred_transport='JSONRPC',
        version='0.1.0',
        capabilities=AgentCapabilities(streaming=True, push_notifications=True),
        default_input_modes=['text'],
        default_output_modes=['text'],
        skills=[
            AgentSkill(
                id='hello_world',
                name='Returns hello world',
                description='returns hello world and emits task status updates',
                tags=['hello world'],
                examples=['hi', 'hello world'],
            )
        ],
        supports_authenticated_extended_card=False,
    )


def build_app():
    agent_card = build_agent_card()

    task_store = InMemoryTaskStore()
    push_config_store = InMemoryPushNotificationConfigStore()

    http_client = httpx.AsyncClient()

    push_sender = SecurePushNotificationSender(
        httpx_client=http_client,
        config_store=push_config_store,
        issuer=os.getenv('A2A_PUSH_ISSUER', 'agentB'),
        audience=os.getenv('A2A_PUSH_AUDIENCE', 'agentA-webhook'),
        ttl_seconds=int(os.getenv('A2A_PUSH_TOKEN_TTL', '60')),
    )

    handler = DefaultRequestHandler(
        agent_executor=HelloWorldExecutor(),
        task_store=task_store,
        push_config_store=push_config_store,
        push_sender=push_sender,
    )

    a2a_app = A2AFastAPIApplication(agent_card=agent_card, http_handler=handler)
    return a2a_app.build()


app = build_app()
