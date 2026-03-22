"""
보안 케이스 검증 — pytest + pytest-asyncio 기반

케이스 구성 (총 11종):
  정상        1종  — 정상 요청
  인증 실패   3종  — Authorization 헤더 누락 / 토큰 만료 / 서명 변조
  jti 재전송  1종  — 동일 jti 재전송
  변형 1      3종  — 구독 외 task JWT 직접 주입 (task-002·003·999로 parametrize)
  변형 2      3종  — 합법 JWT + 위조 payload (task-002·003·999로 parametrize)

실행 방법:
  1. secure_webhook_receiver 서버 실행 (포트 8000):
     uv run python -m uvicorn secure_webhook_receiver:app --app-dir experiments/push_notification --host 0.0.0.0 --port 8000

  2. 테스트 실행:
     uv run pytest experiments/push_notification/test_security_cases.py -v
"""

import asyncio
import os

from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from dotenv import load_dotenv

from experiments.push_notification.test_helpers import make_sender, make_task


load_dotenv(Path(__file__).parent.parent / '.env')

WEBHOOK_URL = os.getenv('WEBHOOK_URL', 'http://127.0.0.1:8000/webhook')
SUBSCRIBED_TASK_ID = 'task-001'
ATTACK_TASK_IDS = ['task-002', 'task-003', 'task-999']


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def client():
    async with httpx.AsyncClient() as c:
        yield c


@pytest_asyncio.fixture
async def sender(client):
    return await make_sender(client, WEBHOOK_URL, SUBSCRIBED_TASK_ID)


@pytest_asyncio.fixture
async def expired_sender(client):
    return await make_sender(client, WEBHOOK_URL, SUBSCRIBED_TASK_ID, ttl=0)


# ── 정상 요청 ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_valid_request(client, sender):
    """정상 JWT + 정상 payload → 200 OK."""
    task = make_task(SUBSCRIBED_TASK_ID)
    token = sender._make_jwt(task, WEBHOOK_URL)
    r = await client.post(
        WEBHOOK_URL,
        json=task.model_dump(mode='json', exclude_none=True),
        headers={'Authorization': f'Bearer {token}'},
    )
    assert r.status_code == 200


# ── 인증 실패 ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_auth_header(client):
    """Authorization 헤더 없음 → 401 (단계 ①)."""
    task = make_task(SUBSCRIBED_TASK_ID)
    r = await client.post(
        WEBHOOK_URL,
        json=task.model_dump(mode='json', exclude_none=True),
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_expired_token(client, expired_sender):
    """TTL=0 JWT를 1초 후 전송 → 401 (단계 ②, exp 검증)."""
    task = make_task(SUBSCRIBED_TASK_ID)
    token = expired_sender._make_jwt(task, WEBHOOK_URL)
    await asyncio.sleep(1)
    r = await client.post(
        WEBHOOK_URL,
        json=task.model_dump(mode='json', exclude_none=True),
        headers={'Authorization': f'Bearer {token}'},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_tampered_jwt(client, sender):
    """서명 마지막 5바이트 변조 → 401 (단계 ②, 서명 검증)."""
    task = make_task(SUBSCRIBED_TASK_ID)
    token = sender._make_jwt(task, WEBHOOK_URL)
    tampered = token[:-5] + 'XXXXX'
    r = await client.post(
        WEBHOOK_URL,
        json=task.model_dump(mode='json', exclude_none=True),
        headers={'Authorization': f'Bearer {tampered}'},
    )
    assert r.status_code == 401


# ── jti 재전송 ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_jti_replay(client, sender):
    """동일 jti 재전송 → 409 (단계 ④, jti 재전송 방지 캐시)."""
    task = make_task(SUBSCRIBED_TASK_ID)
    token = sender._make_jwt(task, WEBHOOK_URL)
    payload = task.model_dump(mode='json', exclude_none=True)
    await client.post(WEBHOOK_URL, json=payload, headers={'Authorization': f'Bearer {token}'})
    r = await client.post(WEBHOOK_URL, json=payload, headers={'Authorization': f'Bearer {token}'})
    assert r.status_code == 409


# ── 변형 1: 직접 주입 ────────────────────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize('attack_task_id', ATTACK_TASK_IDS)
async def test_misbinding_variant1(client, sender, attack_task_id):
    """구독 외 task_id JWT + 동일 payload → 403 (단계 ⑤, 구독 목록 대조 R2)."""
    task = make_task(attack_task_id)
    token = sender._make_jwt(task, WEBHOOK_URL)
    r = await client.post(
        WEBHOOK_URL,
        json=task.model_dump(mode='json', exclude_none=True),
        headers={'Authorization': f'Bearer {token}'},
    )
    assert r.status_code == 403


# ── 변형 2: JWT 재사용 + payload 위조 ────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize('forged_task_id', ATTACK_TASK_IDS)
async def test_misbinding_variant2(client, sender, forged_task_id):
    """합법 JWT(task-001) + 위조 payload(task-00X) → 403 (단계 ⑥, 교차 검증 R3)."""
    legit_task = make_task(SUBSCRIBED_TASK_ID)
    token = sender._make_jwt(legit_task, WEBHOOK_URL)
    forged_payload = make_task(forged_task_id).model_dump(mode='json', exclude_none=True)
    r = await client.post(
        WEBHOOK_URL,
        json=forged_payload,
        headers={'Authorization': f'Bearer {token}'},
    )
    assert r.status_code == 403
