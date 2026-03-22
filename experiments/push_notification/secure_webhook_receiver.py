import json
import logging
import os
import time

from dataclasses import dataclass, field
from typing import Any

import jwt  # PyJWT

from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse


load_dotenv(Path(__file__).parent.parent / '.env')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('secure_webhook_receiver')

# 방식 (2) 비교 실험용 고정 토큰
FIXED_TOKEN = os.getenv('A2A_PUSH_FIXED_TOKEN', 'demo-fixed-token')


@dataclass
class ReceiverConfig:
    """JWT 검증 설정. SecurePushNotificationSender의 JWTConfig와 대응한다.

    Attributes:
        signing_key_env: 서명 시크릿을 담은 환경변수 이름.
        expected_iss:    허용할 ``iss`` 클레임 값 (발신자 식별자).
        expected_aud:    허용할 ``aud`` 클레임 값 (수신자 웹훅 식별자).
        alg:             JWT 서명 알고리즘.
        clock_skew_sec:  허용 시계 오차 (초).
        jti_ttl_sec:     jti 캐시 보존 기간 (초).
    """

    signing_key_env: str = 'A2A_PUSH_JWT_SECRET'
    expected_iss: str = 'agentB'
    expected_aud: str = 'agentA-webhook'
    alg: str = 'HS256'
    clock_skew_sec: int = 30
    jti_ttl_sec: int = field(default=300)


class SecureWebhookReceiver:
    """6단계 JWT 검증을 수행하는 수신자 구현.

    SecurePushNotificationSender가 서명 시점에 바인딩한 task_id 클레임을
    검증하여 Task Misbinding 공격(변형 1·2)과 재전송 공격을 차단한다.

    검증 단계:
        ① Authorization: Bearer 헤더 확인          → 401
        ② JWT 서명·만료·필수 클레임(exp, iat, jti) → 401
        ③ iat 신선도 검증 (clock skew 허용)         → 401
        ④ jti anti-replay 캐시 대조                → 409
        ⑤ JWT.task_id ∈ 구독 목록 대조             → 403 (변형 1 차단)
        ⑥ JWT.task_id == payload.id 교차 검증      → 403 (변형 2 차단)
    """

    def __init__(
        self,
        subscribed_tasks: set[str],
        config: ReceiverConfig | None = None,
    ) -> None:
        self.config = config or ReceiverConfig()
        self.secret = os.getenv(self.config.signing_key_env, '')
        if not self.secret:
            raise RuntimeError(
                f'Missing JWT secret. Set {self.config.signing_key_env} before running.'
            )
        self.subscribed_tasks = subscribed_tasks
        self._jti_cache: dict[str, float] = {}

    # ── 단계 ②: JWT 서명·만료·필수 클레임 검증 ────────────────────────────
    def _decode_jwt(self, token: str) -> dict:
        try:
            return jwt.decode(
                token,
                self.secret,
                algorithms=[self.config.alg],
                audience=self.config.expected_aud,
                issuer=self.config.expected_iss,
                options={
                    'require': ['exp', 'iat', 'jti'],
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': False,
                    'verify_aud': True,
                    'verify_iss': True,
                },
            )
        except jwt.ExpiredSignatureError as e:
            raise HTTPException(status_code=401, detail='JWT expired') from e
        except jwt.InvalidIssuerError as e:
            raise HTTPException(status_code=401, detail='Invalid issuer') from e
        except jwt.InvalidAudienceError as e:
            raise HTTPException(status_code=401, detail='Invalid audience') from e
        except jwt.MissingRequiredClaimError as e:
            raise HTTPException(
                status_code=401, detail=f'Missing required claim: {e.claim}'
            ) from e
        except jwt.PyJWTError as e:
            raise HTTPException(
                status_code=401, detail=f'JWT verification failed: {e!s}'
            ) from e

    # ── 단계 ③④: iat 신선도 + jti anti-replay ─────────────────────────────
    def _check_iat_and_jti(self, claims: dict) -> str:
        now = time.time()
        iat = claims.get('iat')
        if not isinstance(iat, (int, float)):
            raise HTTPException(status_code=401, detail='iat must be a number')
        if iat > now + self.config.clock_skew_sec:
            raise HTTPException(status_code=401, detail='iat is too far in the future')
        if iat < now - (self.config.jti_ttl_sec + self.config.clock_skew_sec):
            raise HTTPException(status_code=401, detail='iat is too old')

        expired = [j for j, exp in self._jti_cache.items() if exp <= now]
        for j in expired:
            self._jti_cache.pop(j, None)

        jti = claims.get('jti')
        if not isinstance(jti, str) or not jti:
            raise HTTPException(status_code=401, detail='Invalid jti')
        if jti in self._jti_cache:
            raise HTTPException(status_code=409, detail='Replay detected (jti already seen)')
        self._jti_cache[jti] = now + self.config.jti_ttl_sec
        return jti

    # ── 전체 6단계 검증 진입점 ─────────────────────────────────────────────
    async def verify(self, request: Request) -> tuple[dict, dict, str]:
        """6단계 검증 수행. 성공 시 (claims, payload, jti) 반환."""
        # ① Authorization: Bearer 헤더 확인
        auth = request.headers.get('authorization') or request.headers.get('Authorization')
        if not auth or not auth.lower().startswith('bearer '):
            raise HTTPException(
                status_code=401, detail='Missing Authorization: Bearer <JWT>'
            )

        token = auth.split(' ', 1)[1].strip()

        # ②③④
        claims = self._decode_jwt(token)
        jti = self._check_iat_and_jti(claims)

        # ⑤ JWT.task_id ∈ 구독 목록 대조 (변형 1 차단)
        task_id = claims.get('task_id') or claims.get('taskId')
        if not isinstance(task_id, str) or not task_id:
            raise HTTPException(status_code=400, detail='Missing task_id claim')
        if self.subscribed_tasks and task_id not in self.subscribed_tasks:
            raise HTTPException(
                status_code=403, detail=f'Task misbinding: {task_id} not subscribed'
            )

        # 페이로드 파싱
        body = await request.body()
        try:
            payload = json.loads(body.decode('utf-8')) if body else {}
        except (ValueError, UnicodeDecodeError):
            payload = {'_raw': body.decode('utf-8', errors='replace')}

        # ⑥ JWT.task_id == payload.id 교차 검증 (변형 2 차단)
        payload_task_id = payload.get('id')
        if payload_task_id and payload_task_id != task_id:
            raise HTTPException(
                status_code=403,
                detail=f'Task misbinding: JWT task_id={task_id!r} != payload id={payload_task_id!r}',
            )

        return claims, payload, jti

    @property
    def jti_cache_size(self) -> int:
        """현재 jti 캐시에 보존된 항목 수를 반환한다."""
        return len(self._jti_cache)


# ── FastAPI 앱 초기화 ───────────────────────────────────────────────────────

_subscribed_raw = os.getenv('A2A_PUSH_SUBSCRIBED_TASKS', '')
SUBSCRIBED_TASKS: set[str] = {
    t.strip() for t in _subscribed_raw.split(',') if t.strip()
}

receiver = SecureWebhookReceiver(
    subscribed_tasks=SUBSCRIBED_TASKS,
    config=ReceiverConfig(
        signing_key_env='A2A_PUSH_JWT_SECRET',
        expected_iss=os.getenv('A2A_PUSH_EXPECTED_ISS', 'agentB'),
        expected_aud=os.getenv('A2A_PUSH_EXPECTED_AUD', 'agentA-webhook'),
        alg=os.getenv('A2A_PUSH_JWT_ALG', 'HS256'),
        clock_skew_sec=int(os.getenv('A2A_PUSH_CLOCK_SKEW_SEC', '30')),
        jti_ttl_sec=int(os.getenv('A2A_PUSH_JTI_TTL_SEC', '300')),
    ),
)

app = FastAPI(title='A2A Webhook Receiver (SecureWebhookReceiver)')


@app.get('/health')
async def health() -> dict[str, Any]:
    return {
        'ok': True,
        'subscribed_tasks': sorted(receiver.subscribed_tasks)
        if receiver.subscribed_tasks
        else ['<ALL>'],
        'jti_cache_size': receiver.jti_cache_size,
    }


@app.post('/webhook-plain')
async def webhook_plain(request: Request) -> JSONResponse:
    """성능 측정용 — 인증 없이 수락 (기존 BasePushNotificationSender 방식)."""
    body = await request.body()
    try:
        payload = json.loads(body.decode('utf-8')) if body else {}
    except ValueError:
        payload = {}
    token = request.headers.get('X-A2A-Notification-Token')
    logger.info(
        '📨 Plain webhook received task_id=%s token=%s',
        payload.get('id'),
        token,
    )
    return JSONResponse({'ok': True})


@app.post('/webhook-token')
async def webhook_token(request: Request) -> JSONResponse:
    """비교 실험용 — 고정 토큰만 확인, task_id 바인딩 없음."""
    token = request.headers.get('X-A2A-Notification-Token', '')
    if token != FIXED_TOKEN:
        raise HTTPException(status_code=401, detail='Invalid token')
    body = await request.body()
    try:
        payload = json.loads(body.decode('utf-8')) if body else {}
    except ValueError:
        payload = {}
    task_id = payload.get('id', '')
    logger.info('📨 Token webhook (no task binding): task_id=%s', task_id)
    return JSONResponse({'ok': True, 'task_id': task_id})


@app.post('/webhook-jwt-notask')
async def webhook_jwt_notask(request: Request) -> JSONResponse:
    """비교 실험용 — JWT 서명 검증, task_id 바인딩 없음."""
    jwt_secret = os.getenv('A2A_PUSH_JWT_SECRET', '')
    jwt_alg = os.getenv('A2A_PUSH_JWT_ALG', 'HS256')
    expected_aud = os.getenv('A2A_PUSH_EXPECTED_AUD', 'agentA-webhook')
    expected_iss = os.getenv('A2A_PUSH_EXPECTED_ISS', 'agentB')

    auth = request.headers.get('authorization') or request.headers.get('Authorization')
    if not auth or not auth.lower().startswith('bearer '):
        raise HTTPException(
            status_code=401, detail='Missing Authorization: Bearer <JWT>'
        )
    token = auth.split(' ', 1)[1].strip()
    try:
        jwt.decode(
            token,
            jwt_secret,
            algorithms=[jwt_alg],
            audience=expected_aud,
            issuer=expected_iss,
            options={
                'require': ['exp', 'iat'],
                'verify_signature': True,
                'verify_exp': True,
                'verify_aud': True,
                'verify_iss': True,
            },
        )
    except jwt.ExpiredSignatureError as err:
        raise HTTPException(status_code=401, detail='JWT expired') from err
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f'JWT error: {e}') from e
    # ❌ task_id 바인딩 검증 없음 — 방식 (3)의 취약점
    body = await request.body()
    try:
        payload = json.loads(body.decode('utf-8')) if body else {}
    except (ValueError, UnicodeDecodeError):
        payload = {}
    task_id = payload.get('id', 'unknown')
    logger.info('📨 JWT-notask webhook (no task binding!): task_id=%s', task_id)
    return JSONResponse({'ok': True, 'task_id': task_id})


@app.post('/webhook')
async def webhook(request: Request) -> JSONResponse:
    """제안 방식 — SecureWebhookReceiver 6단계 검증."""
    claims, payload, jti = await receiver.verify(request)
    task_id = claims.get('task_id') or claims.get('taskId')
    logger.info(
        '✅ Accepted webhook: iss=%s aud=%s task_id=%s jti=%s payload_keys=%s',
        claims.get('iss'),
        claims.get('aud'),
        task_id,
        jti,
        list(payload.keys())[:10],
    )
    return JSONResponse({'ok': True, 'task_id': task_id, 'jti': jti})
