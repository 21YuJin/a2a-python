# Agent Card JWS+JCS 서명/검증 실험

논문 **"A2A Agent Card 위변조 탐지를 위한 JWS 서명 방안"** 의 프로토타입 구현 및 실험.

---

## 구성

```
experiments/agent_card/
├── agent_card_server.py    # FastAPI 서버 — 서명 카드 및 JWKS 서빙 (Algorithm 1)
├── test_helpers.py         # 공유 헬퍼 — 키 생성, 카드 생성, signer/verifier 팩토리
├── test_benchmark.py       # 성능 벤치마크 — 순수 암호 연산 측정 (서버 불필요)
├── test_security_cases.py  # 보안 케이스 — pytest E2E 검증 (서버 필요)
└── tls_diagram.drawio      # 2.2절 TLS 구간 한계 다이어그램
```

---

## 실험 내용

### test_benchmark.py (서버 불필요)

| 실험 | 설명 | N |
|------|------|---|
| 실험 1 | 서명 생성 지연시간 (Algorithm 1) | 1,000 |
| 실험 2 | 서명 검증 지연시간 (Algorithm 2) | 1,000 |
| 실험 3 | 위변조 거부 성공률 (T1~T4 시나리오) | 각 500 |
| 실험 4 | 정상 카드 오검출률 (False Positive) | 1,000 |
| 실험 5 | 서명 없는 카드 거부 | 1,000 |
| 실험 6 | 카드 복잡도(스킬 수)별 성능 비교 | 각 1,000 |

### test_security_cases.py (서버 필요)

| 케이스 | 설명 | 기대 결과 |
|--------|------|-----------|
| 정상 카드 검증 | 서명된 카드 → 검증 성공 | `True` |
| T1 엔드포인트 하이재킹 | URL 교체 감지 | `False` (서명 불일치) |
| T2 인증 다운그레이드 | security 필드 제거 감지 | `False` (서명 불일치) |
| T3 이름 변조 | 에이전트 이름 교체 감지 | `False` (서명 불일치) |
| T4 스킬 권한 확대 | 태그 추가 감지 | `False` (서명 불일치) |
| 서명 부재 | signatures 없는 카드 | `False` (서명 없음) |
| 키 불일치 | 다른 키로 검증 시도 | `False` |
| 서명 바이트 변조 | 서명값 직접 수정 | `False` (서명 불일치) |
| 다중 서명 (유효+무효) | OR 정책 — 하나라도 유효하면 통과 | `True` |
| 재서명 공격 | 공격자 키로 재서명 | `False` |

---

## 실행 방법

### 벤치마크 (서버 불필요)

```bash
PYTHONIOENCODING=utf-8 uv run python -m experiments.agent_card.test_benchmark
```

### 보안 케이스 pytest (서버 필요)

**터미널 1 — 서버 시작:**
```bash
uv run python -m uvicorn agent_card_server:app \
    --app-dir experiments/agent_card --host 0.0.0.0 --port 8001
```

**터미널 2 — 테스트 실행:**
```bash
uv run pytest experiments/agent_card/test_security_cases.py -v
```

---

## 주요 실험 결과 (ES256, N=1,000)

| 항목 | 결과 |
|------|------|
| 서명 생성 평균 | ~0.08 ms |
| 서명 검증 평균 | ~0.11 ms |
| 위변조 거부율 (T1~T4) | **100%** |
| 정상 카드 오검출 | **0%** |
| 스킬 100개 서명 | ~0.5 ms |

> 서명/검증 오버헤드가 1 ms 미만으로, A2A 실시간 통신에 부담 없음을 확인.

---

## 의존성

```
a2a-sdk[signing]
fastapi
uvicorn
httpx
pytest
pytest-asyncio
cryptography
PyJWT
```
