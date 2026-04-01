"""
성능 벤치마크 — JWS+JCS 서명/검증 지연시간 측정 (HTTP 없음, 순수 암호 연산)

측정 항목:
  1. 서명 생성   (Algorithm 1)      — N=1000
  2. 서명 검증   (Algorithm 2)      — N=1000
  3. 위변조 거부율 (T1~T4)          — 각 500회
  4. 오검출률 (False Positive)      — N=1000
  5. 서명 없는 카드 거부             — N=100
  6. 카드 복잡도별 성능 비교         — skills 1/10/50/100개

실행:
  PYTHONIOENCODING=utf-8 uv run python -m experiments.agent_card.test_benchmark
"""

import statistics
import time
import uuid

from a2a.types import AgentCapabilities, AgentCard, AgentSkill
from a2a.utils.signing import InvalidSignaturesError, NoSignatureError

from experiments.agent_card.test_helpers import (
    TAMPER_SCENARIOS,
    make_agent_card,
    make_key_pair,
    make_signer,
    make_verifier,
    verify_card,
)

N_TRIALS = 1000
N_TAMPER = 500


# ── 통계 출력 ─────────────────────────────────────────────────────────────────

def _report(label: str, times_ms: list[float]) -> None:
    s = sorted(times_ms)
    n = len(s)
    print(f"  {label}")
    print(f"    평균:     {statistics.mean(s):.3f} ms")
    print(f"    중앙값:   {statistics.median(s):.3f} ms")
    print(f"    표준편차: {statistics.stdev(s):.3f} ms")
    print(f"    P95:      {s[int(n * 0.95)]:.3f} ms")
    print(f"    P99:      {s[int(n * 0.99)]:.3f} ms")
    print(f"    최소:     {s[0]:.3f} ms  |  최대: {s[-1]:.3f} ms")


# ── 실험 1·2: 서명/검증 지연시간 ─────────────────────────────────────────────

def bench_sign_verify(algorithm: str, signing_jwk, verifying_jwk) -> dict:
    kid = str(uuid.uuid4())
    # signing_jwk/verifying_jwk의 kid를 현재 kid로 맞춘다
    signer = make_signer(kid, signing_jwk)
    verifier = make_verifier({kid: verifying_jwk}, algorithms=[algorithm])

    sign_times: list[float] = []
    verify_times: list[float] = []

    for _ in range(N_TRIALS):
        card = make_agent_card()

        t0 = time.perf_counter()
        signed = signer(card)
        sign_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        verifier(signed)
        verify_times.append((time.perf_counter() - t0) * 1000)

    return {"sign": sign_times, "verify": verify_times}


# ── 실험 3: 위변조 거부율 ────────────────────────────────────────────────────

def bench_tamper_detection(signer, verifier) -> None:
    print(f"\n[실험 3] 위변조 Agent Card 거부 성공률  (N={N_TAMPER}/시나리오)")
    all_pass = True
    for key, (desc, tamper_fn) in TAMPER_SCENARIOS.items():
        rejected = 0
        for _ in range(N_TAMPER):
            card = make_agent_card()
            signed = signer(card)
            tampered = tamper_fn(signed)
            ok, _ = verify_card(tampered, verifier)
            if not ok:
                rejected += 1
        rate = rejected / N_TAMPER * 100
        status = "✅" if rate == 100.0 else "⚠️"
        print(f"  {status} {key:25s} ({desc}): {rate:.1f}%  ({rejected}/{N_TAMPER})")
        if rate < 100.0:
            all_pass = False

    if all_pass:
        print("  → 전 시나리오 100% 거부 확인")


# ── 실험 4: 오검출률 ──────────────────────────────────────────────────────────

def bench_false_positive(signer, verifier) -> None:
    print(f"\n[실험 4] 정상 카드 오검출률 (False Positive)  (N={N_TRIALS})")
    fp = 0
    for _ in range(N_TRIALS):
        card = make_agent_card()
        signed = signer(card)
        ok, _ = verify_card(signed, verifier)
        if not ok:
            fp += 1
    print(f"  오검출(정상 카드 거부): {fp}/{N_TRIALS} = {fp / N_TRIALS * 100:.2f}%")
    if fp == 0:
        print("  ✅ 오검출 없음")


# ── 실험 5: 서명 없는 카드 처리 ───────────────────────────────────────────────

def bench_unsigned_card(verifier) -> None:
    print(f"\n[실험 5] 서명 없는 카드 거부  (N={N_TAMPER})")
    rejected = 0
    for _ in range(N_TAMPER):
        card = make_agent_card()  # signatures=None
        ok, reason = verify_card(card, verifier)
        if not ok and reason == "서명 없음":
            rejected += 1
    print(f"  ✅ 서명 없는 카드 거부: {rejected}/{N_TAMPER}")


# ── 실험 6: 카드 복잡도(스킬 수)별 성능 비교 ────────────────────────────────

def _make_card_with_n_skills(n: int, url: str = "https://agent.example.com") -> AgentCard:
    """스킬 n개를 가진 Agent Card 생성 (JCS 직렬화 크기 다양화)."""
    from a2a.types import AgentCapabilities, AgentCard, AgentSkill
    return AgentCard(
        name="ExperimentAgent",
        description="카드 복잡도 벤치마크용 에이전트",
        url=url,
        version="1.0.0",
        capabilities=AgentCapabilities(streaming=False),
        default_input_modes=["application/json"],
        default_output_modes=["application/json"],
        security=[{"bearer": []}],
        security_schemes={"bearer": {"type": "http", "scheme": "bearer"}},
        skills=[
            AgentSkill(
                id=f"skill-{i:03d}",
                name=f"Skill {i}",
                description=f"스킬 {i}번 설명 — 복잡도 측정용",
                tags=[f"tag-{i}", "benchmark"],
            )
            for i in range(n)
        ],
    )


def bench_complexity(signer, verifier) -> None:
    N = 200  # 복잡도 실험은 200회로 충분
    skill_counts = [1, 10, 50, 100]

    print(f"\n[실험 6] 카드 복잡도(스킬 수)별 성능 비교  (N={N}/조건)")
    header = f"  {'스킬 수':>6}  {'서명 평균':>9}  {'서명 P99':>9}  {'검증 평균':>9}  {'검증 P99':>9}"
    print(header)
    print("  " + "-" * (len(header) - 2))

    for n in skill_counts:
        sign_times: list[float] = []
        verify_times: list[float] = []

        for _ in range(N):
            card = _make_card_with_n_skills(n)

            t0 = time.perf_counter()
            signed = signer(card)
            sign_times.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            verifier(signed)
            verify_times.append((time.perf_counter() - t0) * 1000)

        sm = statistics.mean(sign_times)
        sp99 = sorted(sign_times)[int(N * 0.99)]
        vm = statistics.mean(verify_times)
        vp99 = sorted(verify_times)[int(N * 0.99)]
        print(f"  {n:>6}개  {sm:>8.3f}ms  {sp99:>8.3f}ms  {vm:>8.3f}ms  {vp99:>8.3f}ms")


# ── 메인 ─────────────────────────────────────────────────────────────────────

def run():
    print("=" * 60)
    print("  A2A Agent Card JWS+JCS 서명/검증 벤치마크")
    print(f"  알고리즘: ES256  |  반복: {N_TRIALS}")
    print("=" * 60)

    # ES256 키 / signer / verifier 준비
    kid, signing_jwk, verifying_jwk, _ = make_key_pair()
    signer = make_signer(kid, signing_jwk)
    verifier = make_verifier({kid: verifying_jwk})

    # 실험 1·2
    print(f"\n[실험 1] 서명 생성 지연시간 (Algorithm 1)  (N={N_TRIALS})")
    r = bench_sign_verify("ES256", signing_jwk, verifying_jwk)
    _report("ES256 서명 생성", r["sign"])

    print(f"\n[실험 2] 서명 검증 지연시간 (Algorithm 2)  (N={N_TRIALS})")
    _report("ES256 서명 검증", r["verify"])

    # 실험 3·4·5
    bench_tamper_detection(signer, verifier)
    bench_false_positive(signer, verifier)
    bench_unsigned_card(verifier)

    # 실험 6
    bench_complexity(signer, verifier)

    print("\n" + "=" * 60)
    print("  벤치마크 완료")
    print("=" * 60)


if __name__ == "__main__":
    run()
