"""
Agent Card 서명 서버 (Algorithm 1 구현)

시작 시 EC P-256 키 쌍을 생성하여 Agent Card에 JWS+JCS 서명을 부착한다.

엔드포인트:
  GET /.well-known/agent-card.json          → 서명된 정상 Agent Card
  GET /.well-known/jwks.json                → 공개 키 (JWKS 형식)
  GET /.well-known/agent-card-unsigned.json → 서명 없는 Agent Card (테스트용)
  GET /.well-known/agent-card-tampered.json → 위변조 Agent Card
      ?scenario=T1|T2|T3|T4

실행:
  uv run python -m uvicorn agent_card_server:app \
      --app-dir experiments/agent_card --host 0.0.0.0 --port 8001 --reload
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from experiments.agent_card.test_helpers import (
    TAMPER_SCENARIOS,
    make_agent_card,
    make_key_pair,
    make_signer,
)


# ── 서버 상태 (시작 시 1회 초기화) ───────────────────────────────────────────

_state: dict = {}

SERVER_URL = "http://localhost:8001"
JWKS_URL = f"{SERVER_URL}/.well-known/jwks.json"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Algorithm 1 — 서버 시작 시 키 생성 및 Agent Card 서명."""
    kid, signing_jwk, verifying_jwk, jwks_dict = make_key_pair()
    signer = make_signer(kid, signing_jwk, jwks_url=JWKS_URL)

    # 서명 없는 원본 카드
    unsigned_card = make_agent_card(url=SERVER_URL)
    # 서명 부착
    signed_card = signer(make_agent_card(url=SERVER_URL))

    _state.update(
        kid=kid,
        jwks=jwks_dict,
        signed_card=signed_card,
        unsigned_card=unsigned_card,
    )
    print(f"[서버] kid={kid[:8]}... 키 생성 완료")
    print(f"[서버] Agent Card 서명 완료 (signatures: {len(signed_card.signatures or [])}개)")

    yield  # 서버 실행

    _state.clear()


app = FastAPI(title="Agent Card Signing Server", lifespan=lifespan)


# ── 엔드포인트 ────────────────────────────────────────────────────────────────

@app.get("/.well-known/agent-card.json", summary="서명된 Agent Card")
async def get_signed_agent_card():
    """Algorithm 1 결과물 — JWS+JCS 서명이 부착된 Agent Card."""
    card = _state["signed_card"]
    return JSONResponse(
        content=card.model_dump(mode="json", exclude_none=True),
        headers={"Content-Type": "application/json"},
    )


@app.get("/.well-known/jwks.json", summary="공개 키 (JWKS)")
async def get_jwks():
    """Algorithm 2 Step 2 — 클라이언트가 kid로 공개 키를 조회하는 엔드포인트."""
    return JSONResponse(content=_state["jwks"])


@app.get("/.well-known/agent-card-unsigned.json", summary="서명 없는 Agent Card (테스트용)")
async def get_unsigned_agent_card():
    """서명 필드가 없는 Agent Card — NoSignatureError 검증 시나리오용."""
    card = _state["unsigned_card"]
    return JSONResponse(
        content=card.model_dump(mode="json", exclude_none=True),
    )


@app.get(
    "/.well-known/agent-card-tampered.json",
    summary="위변조 Agent Card (테스트용)",
)
async def get_tampered_agent_card(
    scenario: str = Query(
        default="T1",
        description="위변조 시나리오: T1(엔드포인트) | T2(인증) | T3(이름) | T4(스킬)",
    )
):
    """
    서명된 카드에 위변조를 적용하여 반환.

    클라이언트 측에서 Algorithm 2 검증 시 서명 불일치(InvalidSignaturesError)가
    발생해야 한다.
    """
    scenario_map = {k[:2]: fn for k, (_, fn) in TAMPER_SCENARIOS.items()}
    tamper_fn = scenario_map.get(scenario.upper())
    if tamper_fn is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario '{scenario}'. Use T1, T2, T3, or T4.",
        )

    signed_card = _state["signed_card"]
    tampered = tamper_fn(signed_card)
    return JSONResponse(
        content=tampered.model_dump(mode="json", exclude_none=True),
    )


@app.get("/health")
async def health():
    return {"status": "ok", "kid": _state.get("kid", "")[:8] + "..."}
