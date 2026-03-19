from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx
import jwt

from a2a.server.tasks.base_push_notification_sender import (
    BasePushNotificationSender,
)

if TYPE_CHECKING:
    from a2a.server.tasks.push_notification_config_store import (
        PushNotificationConfigStore,
    )
    from a2a.types import PushNotificationConfig, Task


logger = logging.getLogger(__name__)


@dataclass
class JWTConfig:
    """JWT signing configuration for SecurePushNotificationSender.

    Attributes:
        issuer:          ``iss`` claim — sender identity.
        audience:        ``aud`` claim — intended receiver.
        ttl_seconds:     Token lifetime in seconds.
        signing_key_env: Name of the environment variable holding the signing secret.
        alg:             JWT signing algorithm (e.g. ``'HS256'``).
        timeout:         HTTP request timeout in seconds.
    """

    issuer: str = 'agentB'
    audience: str = 'agentA-webhook'
    ttl_seconds: int = 60
    signing_key_env: str = 'A2A_PUSH_JWT_SECRET'
    alg: str = 'HS256'
    timeout: float = field(default=10.0)


class SecurePushNotificationSender(BasePushNotificationSender):
    """JWT-based push notification sender with task_id binding.

    Defense against Task Misbinding:
    - JWT claim ``task_id`` is bound at signing time to the task being notified.
    - JWT claim ``sub`` is bound to a SHA-256 prefix of the recipient webhook URL,
      preventing a valid token from being forwarded to a different subscriber.

    Receiver MUST verify both the JWT signature AND that ``task_id`` matches the
    task the receiver subscribed to (subscription check).  JWT signing alone is
    insufficient — see §13.2 of the A2A specification.

    JWT claims included:
        iss       sender identity
        aud       intended audience (receiver)
        iat       issued-at (Unix epoch)
        exp       expiry (iat + ttl_seconds)
        jti       unique token ID for anti-replay
        task_id   A2A task identifier bound at signing time
        sub       first 16 hex chars of SHA-256(webhook_url) — recipient binding
    """

    def __init__(
        self,
        httpx_client: httpx.AsyncClient,
        config_store: PushNotificationConfigStore,
        jwt_config: JWTConfig | None = None,
    ) -> None:
        super().__init__(httpx_client=httpx_client, config_store=config_store)
        cfg = jwt_config or JWTConfig()
        self._issuer = cfg.issuer
        self._audience = cfg.audience
        self._ttl_seconds = cfg.ttl_seconds
        self._alg = cfg.alg
        self._timeout = cfg.timeout
        # Validate secret eagerly so misconfiguration fails at startup, not at
        # the first notification attempt.
        self._secret = self._load_secret(cfg.signing_key_env)

    @staticmethod
    def _load_secret(env_var: str) -> str:
        secret = os.getenv(env_var, '')
        if not secret:
            raise RuntimeError(
                f'Missing env {env_var}. Set it before running the agent.'
            )
        return secret

    @staticmethod
    def _url_fingerprint(url: str) -> str:
        """Return first 16 hex chars of SHA-256(url) as a recipient binding claim."""
        return hashlib.sha256(url.encode()).hexdigest()[:16]

    def _make_jwt(self, task: Task, webhook_url: str) -> str:
        """Issue a JWT whose claims are bound to both *task* and *webhook_url*.

        Binding ``task_id`` prevents misbinding across tasks.
        Binding ``sub`` (URL fingerprint) prevents token forwarding to a
        different subscriber that shares the same secret.
        """
        now = int(time.time())
        payload = {
            'iss': self._issuer,
            'aud': self._audience,
            'iat': now,
            'exp': now + self._ttl_seconds,
            'jti': str(uuid.uuid4()),
            'task_id': task.id,
            'sub': self._url_fingerprint(webhook_url),
        }
        return jwt.encode(payload, self._secret, algorithm=self._alg)

    async def _dispatch_notification(
        self, task: Task, push_info: PushNotificationConfig
    ) -> bool:
        url = push_info.url
        try:
            jwt_token = self._make_jwt(task, url)
            headers = {'Authorization': f'Bearer {jwt_token}'}
            response = await self._client.post(
                url,
                json=task.model_dump(mode='json', exclude_none=True),
                headers=headers,
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.TimeoutException:
            logger.exception(
                'Timeout sending push task_id=%s to %s', task.id, url
            )
            return False
        except httpx.HTTPStatusError as exc:
            logger.exception(
                'HTTP %s for push task_id=%s to %s',
                exc.response.status_code,
                task.id,
                url,
            )
            return False
        except httpx.RequestError:
            logger.exception(
                'Network error sending push task_id=%s to %s', task.id, url
            )
            return False
        else:
            logger.info(
                'Secure push sent task_id=%s to %s status=%s',
                task.id,
                url,
                response.status_code,
            )
            return True
