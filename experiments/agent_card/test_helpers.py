"""공통 테스트 헬퍼 — 키 생성, 카드 생성, signer/verifier 팩토리."""

import json
import uuid

from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from jwt.api_jwk import PyJWK

from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
)
from a2a.utils.signing import (
    InvalidSignaturesError,
    NoSignatureError,
    create_agent_card_signer,
    create_signature_verifier,
)

ALGORITHM = "ES256"


# ── 키 생성 ──────────────────────────────────────────────────────────────────

def make_key_pair(kid: str | None = None) -> tuple[str, PyJWK, PyJWK, dict]:
    """EC P-256 키 쌍을 생성하고 (kid, signing_jwk, verifying_jwk, jwks_dict) 반환.

    Returns:
        kid:          키 식별자 (UUID)
        signing_jwk:  서명용 비공개 키 (PyJWK)
        verifying_jwk: 검증용 공개 키 (PyJWK)
        jwks_dict:    /.well-known/jwks.json 응답 형식의 dict
    """
    if kid is None:
        kid = str(uuid.uuid4())

    private_key = ec.generate_private_key(ec.SECP256R1())
    priv_dict = json.loads(ECAlgorithm.to_jwk(private_key))
    pub_dict = json.loads(ECAlgorithm.to_jwk(private_key.public_key()))

    for d in (priv_dict, pub_dict):
        d.update({"kid": kid, "alg": ALGORITHM, "use": "sig"})

    signing_jwk = PyJWK.from_dict(priv_dict)
    verifying_jwk = PyJWK.from_dict(pub_dict)
    jwks_dict = {"keys": [pub_dict]}

    return kid, signing_jwk, verifying_jwk, jwks_dict


# ── Agent Card 생성 ───────────────────────────────────────────────────────────

def make_agent_card(url: str = "https://agent.example.com") -> AgentCard:
    """실험용 Agent Card 생성.

    security / security_schemes 필드를 포함하여 T2 시나리오(인증 다운그레이드)가
    JCS 정규화 변화를 통해 정상 감지되도록 한다.
    """
    return AgentCard(
        name="ExperimentAgent",
        description="A2A Agent Card JWS 서명 실험용 에이전트",
        url=url,
        version="1.0.0",
        capabilities=AgentCapabilities(streaming=False),
        default_input_modes=["application/json"],
        default_output_modes=["application/json"],
        security=[{"bearer": []}],
        security_schemes={
            "bearer": {"type": "http", "scheme": "bearer"}
        },
        skills=[
            AgentSkill(
                id="skill-echo",
                name="Echo",
                description="입력을 그대로 반환하는 스킬",
                tags=["echo"],
            )
        ],
    )


# ── Signer / Verifier 팩토리 ─────────────────────────────────────────────────

def make_signer(kid: str, signing_jwk: PyJWK, jwks_url: str | None = None):
    """논문 Algorithm 1 — JCS 정규화 후 ES256 서명하는 callable 반환."""
    return create_agent_card_signer(
        signing_key=signing_jwk,
        protected_header={
            "kid": kid,
            "alg": ALGORITHM,
            "jku": jwks_url,
            "typ": "JOSE",
        },
    )


def make_verifier(key_store: dict[str, PyJWK], algorithms: list[str] | None = None):
    """논문 Algorithm 2 — kid로 공개 키를 조회하여 서명 검증하는 callable 반환.

    Args:
        key_store: {kid: PyJWK} 형태의 인메모리 JWKS 캐시
        algorithms: 허용 알고리즘 목록 (기본: [ALGORITHM])
    """
    if algorithms is None:
        algorithms = [ALGORITHM]

    def key_provider(kid: str | None, jku: str | None) -> PyJWK:
        if kid and kid in key_store:
            return key_store[kid]
        raise KeyError(f"Unknown kid: {kid!r}")

    return create_signature_verifier(
        key_provider=key_provider,
        algorithms=algorithms,
    )


# ── 위변조 시나리오 ───────────────────────────────────────────────────────────

def tamper_t1_endpoint(card: AgentCard) -> AgentCard:
    """T1: 엔드포인트 하이재킹 — 서비스 URL을 공격자 서버로 교체."""
    t = card.model_copy(deep=True)
    t.url = "https://attacker.evil.com/hijacked"
    return t


def tamper_t2_auth_downgrade(card: AgentCard) -> AgentCard:
    """T2: 인증 다운그레이드 — security / security_schemes 필드 제거."""
    t = card.model_copy(deep=True)
    t.security = None
    t.security_schemes = None
    return t


def tamper_t3_name(card: AgentCard) -> AgentCard:
    """T3: 에이전트 이름 변조 — 피싱 에이전트로 교체."""
    t = card.model_copy(deep=True)
    t.name = "MaliciousAgent"
    return t


def tamper_t4_skill(card: AgentCard) -> AgentCard:
    """T4: 스킬 권한 확대 — 기존 스킬 태그에 고권한 태그 추가."""
    t = card.model_copy(deep=True)
    if t.skills:
        original = t.skills[0]
        t.skills = [
            AgentSkill(
                id=original.id,
                name=original.name,
                description=original.description,
                tags=(original.tags or []) + ["admin", "sudo"],
            )
        ]
    return t


TAMPER_SCENARIOS: dict[str, tuple[str, callable]] = {
    "T1_endpoint_hijack":   ("엔드포인트 하이재킹",   tamper_t1_endpoint),
    "T2_auth_downgrade":    ("인증 다운그레이드",      tamper_t2_auth_downgrade),
    "T3_name_spoofing":     ("에이전트 이름 변조",     tamper_t3_name),
    "T4_skill_escalation":  ("스킬 권한 확대",         tamper_t4_skill),
}


# ── 검증 유틸 ─────────────────────────────────────────────────────────────────

def verify_card(card: AgentCard, verifier) -> tuple[bool, str]:
    """서명 검증을 수행하고 (성공 여부, 사유) 튜플 반환."""
    try:
        verifier(card)
        return True, "OK"
    except NoSignatureError:
        return False, "서명 없음"
    except InvalidSignaturesError:
        return False, "서명 불일치"
    except Exception as e:
        return False, str(e)


def check(label: str, ok: bool, reason: str = "") -> bool:
    """결과를 stdout에 출력하고 성공 여부 반환."""
    mark = "✅" if ok else "❌"
    detail = f" ({reason})" if reason and reason != "OK" else ""
    print(f"  {mark} {label}{detail}")
    return ok
