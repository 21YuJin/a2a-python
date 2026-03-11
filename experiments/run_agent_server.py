import logging
import os
import uuid

import httpx

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
    TextPart,
)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('run_agent_server')


class HelloWorldExecutor(AgentExecutor):
    async def execute(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        msg = Message(
            message_id=str(uuid.uuid4()),
            role=Role.agent,
            parts=[Part(root=TextPart(text='Hello World'))],
            task_id=context.task_id,
            context_id=context.context_id,
        )
        await event_queue.enqueue_event(msg)

    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        # Minimal no-op cancel implementation for the demo
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
                description='just returns hello world',
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
