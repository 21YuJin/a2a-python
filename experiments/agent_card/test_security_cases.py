"""
보안 케이스 검증 — pytest + httpx 기반 (서버 대상 End-to-End)

케이스 구성 (총 10종):
  정상        1종  — 서명된 카드 검증 성공
  위변조      4종  — T1(URL) / T2(인증) / T3(이름) / T4(스킬) 감지
  서명 부재   1종  — 서명 없는 카드 거부
  키 불일치   1종  — 다른 키로 서명된 카드 거부
  서명 직접변조 1종 — 서명값 바이트 변조 거부
  다중 서명   1종  — 유효 서명 1개 + 무효 서명 1개 → 검증 성공
  재서명 공격 1종  — 공격자 키로 재서명한 카드 거부 (kid 불일치)

사전 조건:
  서버 실행:
    uv run python -m uvicorn agent_card_server:app \
        --app-dir experiments/agent_card --host 0.0.0.0 --port 8001

실행:
  uv run pytest experiments/agent_card/test_security_cases.py -v
"""

import pytest
import pytest_asyncio
import httpx

from a2a.types import AgentCard
from a2a.utils.signing import InvalidSignaturesError, NoSignatureError

from experiments.agent_card.test_helpers import (
    make_agent_card,
    make_key_pair,
    make_signer,
    make_verifier,
    verify_card,
    tamper_t1_endpoint,
    tamper_t2_auth_downgrade,
    tamper_t3_name,
    tamper_t4_skill,
)

BASE_URL = "http://localhost:8001"


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="session")
async def http_client():
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as c:
        yield c


@pytest_asyncio.fixture(scope="session")
async def server_jwks(http_client):
    """서버에서 JWKS 한 번만 조회 (세션 범위)."""
    r = await http_client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    return r.json()


@pytest_asyncio.fixture(scope="session")
async def server_verifier(server_jwks):
    """JWKS로 구성한 서명 검증기."""
    from jwt.api_jwk import PyJWK
    key_store: dict[str, PyJWK] = {}
    for jwk_dict in server_jwks.get("keys", []):
        kid = jwk_dict.get("kid")
        if kid:
            key_store[kid] = PyJWK.from_dict(jwk_dict)
    return make_verifier(key_store)


@pytest_asyncio.fixture(scope="session")
async def signed_card(http_client):
    """서버에서 서명된 카드 한 번만 조회."""
    r = await http_client.get("/.well-known/agent-card.json")
    assert r.status_code == 200
    return AgentCard.model_validate(r.json())


# ── 정상 케이스 ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_valid_card_verification(signed_card, server_verifier):
    """서명된 정상 카드는 검증에 성공해야 한다."""
    ok, reason = verify_card(signed_card, server_verifier)
    assert ok, f"정상 카드가 거부됨: {reason}"


# ── 위변조 감지 ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tamper_t1_endpoint(http_client, server_verifier):
    """T1: 서버 반환 위변조 카드(T1)는 검증에 실패해야 한다."""
    r = await http_client.get("/.well-known/agent-card-tampered.json?scenario=T1")
    assert r.status_code == 200
    card = AgentCard.model_validate(r.json())
    ok, reason = verify_card(card, server_verifier)
    assert not ok, "T1 위변조 카드가 검증을 통과함 (오탐)"
    assert reason == "서명 불일치"


@pytest.mark.asyncio
async def test_tamper_t2_auth_downgrade(http_client, server_verifier):
    """T2: 인증 다운그레이드 카드는 검증에 실패해야 한다."""
    r = await http_client.get("/.well-known/agent-card-tampered.json?scenario=T2")
    assert r.status_code == 200
    card = AgentCard.model_validate(r.json())
    ok, reason = verify_card(card, server_verifier)
    assert not ok, "T2 위변조 카드가 검증을 통과함 (오탐)"
    assert reason == "서명 불일치"


@pytest.mark.asyncio
async def test_tamper_t3_name_spoofing(http_client, server_verifier):
    """T3: 이름 변조 카드는 검증에 실패해야 한다."""
    r = await http_client.get("/.well-known/agent-card-tampered.json?scenario=T3")
    assert r.status_code == 200
    card = AgentCard.model_validate(r.json())
    ok, reason = verify_card(card, server_verifier)
    assert not ok, "T3 위변조 카드가 검증을 통과함 (오탐)"
    assert reason == "서명 불일치"


@pytest.mark.asyncio
async def test_tamper_t4_skill_escalation(http_client, server_verifier):
    """T4: 스킬 권한 확대 카드는 검증에 실패해야 한다."""
    r = await http_client.get("/.well-known/agent-card-tampered.json?scenario=T4")
    assert r.status_code == 200
    card = AgentCard.model_validate(r.json())
    ok, reason = verify_card(card, server_verifier)
    assert not ok, "T4 위변조 카드가 검증을 통과함 (오탐)"
    assert reason == "서명 불일치"


# ── 서명 부재 ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unsigned_card_rejected(http_client, server_verifier):
    """서명 없는 카드는 NoSignatureError로 거부되어야 한다."""
    r = await http_client.get("/.well-known/agent-card-unsigned.json")
    assert r.status_code == 200
    card = AgentCard.model_validate(r.json())
    ok, reason = verify_card(card, server_verifier)
    assert not ok, "서명 없는 카드가 검증을 통과함"
    assert reason == "서명 없음"


# ── 키 불일치 ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_wrong_key_rejected(signed_card):
    """다른 키 쌍으로 구성된 verifier는 서버 카드를 거부해야 한다."""
    kid2, _, vk2, _ = make_key_pair()
    # kid를 서버 카드의 kid와 동일하게 설정해도 실제 키가 달라 실패해야 함
    server_kid = signed_card.signatures[0].protected
    # 잘못된 키를 동일 kid에 매핑
    wrong_verifier = make_verifier({server_kid: vk2})
    ok, reason = verify_card(signed_card, wrong_verifier)
    assert not ok, "키 불일치인데 검증을 통과함"


# ── 서명값 직접 변조 ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_signature_bytes_tampered(signed_card, server_verifier):
    """서명 바이트 마지막 5자리를 변조하면 검증에 실패해야 한다."""
    tampered = signed_card.model_copy(deep=True)
    original_sig = tampered.signatures[0].signature
    tampered.signatures[0].signature = original_sig[:-5] + "XXXXX"
    ok, reason = verify_card(tampered, server_verifier)
    assert not ok, "서명 바이트 변조 카드가 검증을 통과함"
    assert reason == "서명 불일치"


# ── 다중 서명 (유효 1 + 무효 1) ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_multi_signature_one_valid(server_verifier):
    """유효 서명 1개 + 무효 서명 1개가 있을 때 검증은 성공해야 한다 (OR 정책)."""
    from a2a.types import AgentCardSignature

    kid, sk, vk, _ = make_key_pair()
    signer = make_signer(kid, sk)
    card = signer(make_agent_card())

    # 무효 서명 추가 (서명값 변조)
    fake_sig = AgentCardSignature(
        protected=card.signatures[0].protected,
        signature="aW52YWxpZHNpZ25hdHVyZQ",  # base64url("invalidsignature")
    )
    card.signatures = card.signatures + [fake_sig]

    local_verifier = make_verifier({kid: vk})
    ok, reason = verify_card(card, local_verifier)
    assert ok, f"유효 서명이 포함된 다중 서명 카드가 거부됨: {reason}"


# ── 재서명 공격 ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_resign_attack_rejected(signed_card, server_verifier):
    """공격자가 자신의 키로 재서명한 카드를 서버 verifier가 거부해야 한다.

    공격자 kid가 서버 key_store에 없으므로 KeyError → InvalidSignaturesError.
    """
    attacker_kid, attacker_sk, _, _ = make_key_pair()
    attacker_signer = make_signer(attacker_kid, attacker_sk)

    # 서버 카드를 기반으로 서명 제거 후 공격자 키로 재서명
    stripped = signed_card.model_copy(deep=True)
    stripped.signatures = None
    resigned = attacker_signer(stripped)

    ok, _ = verify_card(resigned, server_verifier)
    assert not ok, "재서명 공격 카드가 서버 verifier를 통과함"
