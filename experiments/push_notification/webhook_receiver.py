import json
import logging
import os
import time

from typing import Any

import jwt  # PyJWT

from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse


load_dotenv(Path(__file__).parent.parent / '.env')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('webhook_receiver')

# ===== Config =====
JWT_SECRET = os.getenv('A2A_PUSH_JWT_SECRET', '')
JWT_ALG = os.getenv('A2A_PUSH_JWT_ALG', 'HS256')
EXPECTED_ISS = os.getenv('A2A_PUSH_EXPECTED_ISS', 'agentB')
EXPECTED_AUD = os.getenv('A2A_PUSH_EXPECTED_AUD', 'agentA-webhook')

# Allow small clock skew (seconds)
CLOCK_SKEW_SEC = int(os.getenv('A2A_PUSH_CLOCK_SKEW_SEC', '30'))
# Anti-replay cache TTL (seconds)
JTI_TTL_SEC = int(os.getenv('A2A_PUSH_JTI_TTL_SEC', '300'))

# Demo: subscribed task ids (comma-separated). If empty => allow all (not recommended)
_subscribed_raw = os.getenv('A2A_PUSH_SUBSCRIBED_TASKS', '')
SUBSCRIBED_TASKS: set[str] = set(
    t.strip() for t in _subscribed_raw.split(',') if t.strip()
)

# In-memory anti-replay cache: jti -> exp_time_epoch
JTI_CACHE: dict[str, float] = {}

# 방식 (2) 비교 실험용 고정 토큰
FIXED_TOKEN = os.getenv('A2A_PUSH_FIXED_TOKEN', 'demo-fixed-token')


def _purge_expired_jtis(now: float) -> None:
    # Simple purge to keep dict small
    expired = [jti for jti, exp in JTI_CACHE.items() if exp <= now]
    for jti in expired:
        JTI_CACHE.pop(jti, None)


def _decode_jwt(token: str) -> dict:
    """JWT 서명·만료·필수클레임 검증 후 claims 반환. 실패 시 HTTPException 발생."""
    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALG],
            audience=EXPECTED_AUD,
            issuer=EXPECTED_ISS,
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


def _check_iat_and_jti(claims: dict) -> str:
    """Check iat freshness and jti anti-replay; return jti or raise HTTPException."""
    now = time.time()
    iat = claims.get('iat')
    if not isinstance(iat, (int, float)):
        raise HTTPException(status_code=401, detail='iat must be a number')
    if iat > now + CLOCK_SKEW_SEC:
        raise HTTPException(status_code=401, detail='iat is too far in the future')
    if iat < now - (JTI_TTL_SEC + CLOCK_SKEW_SEC):
        raise HTTPException(status_code=401, detail='iat is too old')

    _purge_expired_jtis(now)
    jti = claims.get('jti')
    if not isinstance(jti, str) or not jti:
        raise HTTPException(status_code=401, detail='Invalid jti')
    if jti in JTI_CACHE:
        raise HTTPException(status_code=409, detail='Replay detected (jti already seen)')
    JTI_CACHE[jti] = now + JTI_TTL_SEC
    return jti


def _require_env() -> None:
    if not JWT_SECRET:
        raise RuntimeError(
            'Missing env A2A_PUSH_JWT_SECRET. Set it before running.'
        )


app = FastAPI(title='A2A Webhook Receiver (JWT Verified)')


@app.get('/health')
async def health() -> dict[str, Any]:
    return {
        'ok': True,
        'subscribed_tasks': sorted(list(SUBSCRIBED_TASKS))
        if SUBSCRIBED_TASKS
        else ['<ALL>'],
        'jti_cache_size': len(JTI_CACHE),
    }


@app.post('/webhook-plain')
async def webhook_plain(request: Request) -> JSONResponse:
    """성능 측정용 - 인증 없이 수락 (기존 BasePushNotificationSender 방식)."""
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
    """비교 실험용 - 방식 (2): 단순 고정 토큰만 확인, task_id 바인딩 없음."""
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
    """비교 실험용 - 방식 (3): JWT 서명 검증, task_id 바인딩 없음."""
    _require_env()
    auth = request.headers.get('authorization') or request.headers.get(
        'Authorization'
    )
    if not auth or not auth.lower().startswith('bearer '):
        raise HTTPException(
            status_code=401, detail='Missing Authorization: Bearer <JWT>'
        )
    token = auth.split(' ', 1)[1].strip()
    try:
        jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALG],
            audience=EXPECTED_AUD,
            issuer=EXPECTED_ISS,
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
    # ❌ task_id 바인딩 검증 없음 — 이것이 방식 (3)의 취약점
    body = await request.body()
    try:
        payload = json.loads(body.decode('utf-8')) if body else {}
    except Exception:
        payload = {}
    task_id = payload.get('id', 'unknown')
    logger.info('📨 JWT-notask webhook (no task binding!): task_id=%s', task_id)
    return JSONResponse({'ok': True, 'task_id': task_id})


@app.post('/webhook')
async def webhook(request: Request):
    _require_env()

    auth = request.headers.get('authorization') or request.headers.get(
        'Authorization'
    )
    if not auth or not auth.lower().startswith('bearer '):
        raise HTTPException(
            status_code=401, detail='Missing Authorization: Bearer <JWT>'
        )

    token = auth.split(' ', 1)[1].strip()
    claims = _decode_jwt(token)
    jti = _check_iat_and_jti(claims)

    # Task binding check
    task_id = claims.get('task_id') or claims.get('taskId')
    if not isinstance(task_id, str) or not task_id:
        raise HTTPException(status_code=400, detail='Missing task_id claim')

    if SUBSCRIBED_TASKS and task_id not in SUBSCRIBED_TASKS:
        raise HTTPException(
            status_code=403, detail=f'Task misbinding: {task_id} not subscribed'
        )

    # Read body (Task JSON snapshot)
    body = await request.body()
    try:
        payload = json.loads(body.decode('utf-8')) if body else {}
    except Exception:
        payload = {'_raw': body.decode('utf-8', errors='replace')}

    # Cross-check: JWT claim task_id must match payload task id
    # Prevents stolen-JWT replay: attacker reuses JWT(task-001) with task-003 payload
    payload_task_id = payload.get('id')
    if payload_task_id and payload_task_id != task_id:
        raise HTTPException(
            status_code=403,
            detail=f'Task misbinding: JWT task_id={task_id!r} != payload id={payload_task_id!r}',
        )

    logger.info(
        '✅ Accepted webhook: iss=%s aud=%s task_id=%s jti=%s payload_keys=%s',
        claims.get('iss'),
        claims.get('aud'),
        task_id,
        jti,
        list(payload.keys())[:10],
    )

    return JSONResponse({'ok': True, 'task_id': task_id, 'jti': jti})
