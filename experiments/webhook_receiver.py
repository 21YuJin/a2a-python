import json
import logging
import os
import time

from typing import Any

import jwt  # PyJWT

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse


load_dotenv()

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


def _purge_expired_jtis(now: float) -> None:
    # Simple purge to keep dict small
    expired = [jti for jti, exp in JTI_CACHE.items() if exp <= now]
    for jti in expired:
        JTI_CACHE.pop(jti, None)


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

    # Decode and verify JWT (HS256)
    try:
        # By default, PyJWT verifies exp if present.
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALG],
            audience=EXPECTED_AUD,
            issuer=EXPECTED_ISS,
            options={
                'require': ['exp', 'iat', 'jti'],
                'verify_signature': True,
                'verify_exp': True,
                'verify_iat': False,  # we'll check iat with skew ourselves
                'verify_aud': True,
                'verify_iss': True,
            },
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='JWT expired')
    except jwt.InvalidIssuerError:
        raise HTTPException(status_code=401, detail='Invalid issuer')
    except jwt.InvalidAudienceError:
        raise HTTPException(status_code=401, detail='Invalid audience')
    except jwt.MissingRequiredClaimError as e:
        raise HTTPException(
            status_code=401, detail=f'Missing required claim: {e.claim}'
        )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=401, detail=f'JWT verification failed: {e!s}'
        )

    now = time.time()

    # iat freshness check (optional but recommended)
    iat = claims.get('iat')
    if isinstance(iat, (int, float)):
        # iat should not be too far in the future
        if iat > now + CLOCK_SKEW_SEC:
            raise HTTPException(
                status_code=401, detail='iat is too far in the future'
            )
        # optionally: reject very old tokens (beyond jti ttl + skew)
        if iat < now - (JTI_TTL_SEC + CLOCK_SKEW_SEC):
            raise HTTPException(status_code=401, detail='iat is too old')
    else:
        raise HTTPException(status_code=401, detail='iat must be a number')

    # Anti-replay (jti cache)
    _purge_expired_jtis(now)
    jti = claims.get('jti')
    if not isinstance(jti, str) or not jti:
        raise HTTPException(status_code=401, detail='Invalid jti')
    if jti in JTI_CACHE:
        raise HTTPException(
            status_code=409, detail='Replay detected (jti already seen)'
        )
    # Store jti with TTL (use now + JTI_TTL_SEC)
    JTI_CACHE[jti] = now + JTI_TTL_SEC

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

    logger.info(
        '✅ Accepted webhook: iss=%s aud=%s task_id=%s jti=%s payload_keys=%s',
        claims.get('iss'),
        claims.get('aud'),
        task_id,
        jti,
        list(payload.keys())[:10],
    )

    return JSONResponse({'ok': True, 'task_id': task_id, 'jti': jti})
