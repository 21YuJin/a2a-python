import logging
import os
import time
import uuid

import httpx
import jwt

from a2a.server.tasks.base_push_notification_sender import (
    BasePushNotificationSender,
)
from a2a.server.tasks.push_notification_config_store import (
    PushNotificationConfigStore,
)
from a2a.types import PushNotificationConfig, Task


logger = logging.getLogger(__name__)


class SecurePushNotificationSender(BasePushNotificationSender):
    """HS256-based secure sender:
    - Adds Authorization: Bearer <JWT>
    - JWT claims: iss, aud, iat, exp, jti, task_id
    """

    def __init__(
        self,
        httpx_client: httpx.AsyncClient,
        config_store: PushNotificationConfigStore,
        *,
        issuer: str = 'agentB',
        audience: str = 'agentA-webhook',
        ttl_seconds: int = 60,
        secret_env: str = 'A2A_PUSH_JWT_SECRET',
        alg: str = 'HS256',
    ) -> None:
        super().__init__(httpx_client=httpx_client, config_store=config_store)
        self._issuer = issuer
        self._audience = audience
        self._ttl_seconds = ttl_seconds
        self._secret_env = secret_env
        self._alg = alg

    def _get_secret(self) -> str:
        secret = os.getenv(self._secret_env, '')
        if not secret:
            raise RuntimeError(
                f'Missing env {self._secret_env}. Set it before running the agent.'
            )
        return secret

    def _make_jwt(self, task: Task) -> str:
        now = int(time.time())
        payload = {
            'iss': self._issuer,
            'aud': self._audience,
            'iat': now,
            'exp': now + self._ttl_seconds,
            'jti': str(uuid.uuid4()),
            'task_id': task.id,
        }
        token = jwt.encode(payload, self._get_secret(), algorithm=self._alg)
        return token

    async def _dispatch_notification(
        self, task: Task, push_info: PushNotificationConfig
    ) -> bool:
        """Override BasePushNotificationSender._dispatch_notification:
        - keep existing behavior (POST task JSON)
        - add Authorization: Bearer JWT
        - keep X-A2A-Notification-Token if present (optional)
        """
        url = push_info.url
        try:
            headers = {}

            # keep optional token header if configured
            if push_info.token:
                headers['X-A2A-Notification-Token'] = push_info.token

            # add JWT auth header
            jwt_token = self._make_jwt(task)
            headers['Authorization'] = f'Bearer {jwt_token}'

            response = await self._client.post(
                url,
                json=task.model_dump(mode='json', exclude_none=True),
                headers=headers,
                timeout=10.0,
            )
            response.raise_for_status()
            logger.info(
                'Secure push sent task_id=%s to %s status=%s',
                task.id,
                url,
                response.status_code,
            )
            return True
        except Exception:
            logger.exception(
                'Error sending secure push task_id=%s to URL: %s',
                task.id,
                url,
            )
            return False
