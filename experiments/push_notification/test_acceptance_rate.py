"""
논문 §4.2 보안 요구사항 검증 — 공격 수락률 비교 실험

기존 SDK(BasePushNotificationSender) vs 제안 방식(SecurePushNotificationSender)에
변형 1·2 공격을 N회 반복 전송하여 수락률을 정량 비교한다.

실험 설계:
  수신자 구독 태스크: task-001
  공격 태스크:        task-002, task-003, task-999 (3종 × N회)

  변형 1 (직접 주입):
    - 기존 수신자(/webhook-plain):     task_id 검증 없음 → 수락
    - 기존 수신자(/webhook-jwt-notask): JWT 서명만 검증 → 수락
    - 제안 수신자(/webhook):            JWT.task_id 구독 대조 → 거부

  변형 2 (JWT 재사용 + payload 위조):
    - 기존 수신자(/webhook-jwt-notask): JWT.task_id vs payload.id 교차검증 없음 → 수락
    - 제안 수신자(/webhook):            교차검증 → 거부

실행 방법:
  1. secure_webhook_receiver 서버 실행 (포트 8000):
     uv run python -m uvicorn secure_webhook_receiver:app \
       --app-dir experiments/push_notification --host 0.0.0.0 --port 8000

  2. 환경변수:
     A2A_PUSH_JWT_SECRET=<secret>
     A2A_PUSH_SUBSCRIBED_TASKS=task-001

  3. 실행:
     uv run python -m experiments.push_notification.test_acceptance_rate
"""

import asyncio
import os

from pathlib import Path

import httpx

from dotenv import load_dotenv

from a2a.server.tasks.inmemory_push_notification_config_store import (
    InMemoryPushNotificationConfigStore,
)
from a2a.server.tasks.secure_push_notification_sender import (
    JWTConfig,
    SecurePushNotificationSender,
)
from experiments.push_notification.test_helpers import make_task


load_dotenv(Path(__file__).parent.parent / '.env')

BASE_URL = os.getenv('WEBHOOK_BASE_URL', 'http://127.0.0.1:8000')
SECRET = os.getenv('A2A_PUSH_JWT_SECRET', '')
ISS = os.getenv('A2A_PUSH_ISSUER', 'agentB')
AUD = os.getenv('A2A_PUSH_EXPECTED_AUD', 'agentA-webhook')
FIXED_TOKEN = os.getenv('A2A_PUSH_FIXED_TOKEN', 'demo-fixed-token')

SUBSCRIBED_TASK = 'task-001'
ATTACK_TASKS = ['task-002', 'task-003', 'task-999']
N_REPEAT = 10  # 공격 태스크 1종당 반복 횟수


# ── 수락률 집계 ──────────────────────────────────────────────────────────────


class AcceptCounter:
    def __init__(self, total: int) -> None:
        self.total = total
        self.accepted = 0
        self.rejected = 0

    def record(
        self, status_code: int, accept_codes: tuple[int, ...] = (200,)
    ) -> None:
        if status_code in accept_codes:
            self.accepted += 1
        else:
            self.rejected += 1

    @property
    def accept_rate(self) -> float:
        return self.accepted / self.total * 100 if self.total else 0.0

    def summary(self) -> str:
        return f'{self.accepted}/{self.total} 수락 ({self.accept_rate:.0f}%)'


# ── 공격 전송 헬퍼 ───────────────────────────────────────────────────────────


def _make_attack_sender(
    client: httpx.AsyncClient,
) -> SecurePushNotificationSender:
    """공격자가 보유한 SecurePushNotificationSender (서명 키는 공유, 구독은 없음)."""
    config_store = InMemoryPushNotificationConfigStore()
    return SecurePushNotificationSender(
        httpx_client=client,
        config_store=config_store,
        jwt_config=JWTConfig(issuer=ISS, audience=AUD, ttl_seconds=60),
    )


async def _variant1_existing(
    client: httpx.AsyncClient,
    sender: SecurePushNotificationSender,
    attack_task_id: str,
) -> tuple[int, int]:
    """변형 1 — 기존 수신자 대상.

    /webhook-plain  : 인증 없이 수락 (BasePushNotificationSender 방식)
    /webhook-jwt-notask: JWT 서명만 검증, task_id 미대조
    둘 다 공격 수락 → 수락 2건.
    """
    attack_task = make_task(attack_task_id, text='variant1 attack')
    attack_payload = attack_task.model_dump(mode='json', exclude_none=True)
    attack_jwt = sender._make_jwt(attack_task, f'{BASE_URL}/webhook')

    r_plain = await client.post(
        f'{BASE_URL}/webhook-plain',
        json=attack_payload,
    )
    r_notask = await client.post(
        f'{BASE_URL}/webhook-jwt-notask',
        json=attack_payload,
        headers={'Authorization': f'Bearer {attack_jwt}'},
    )
    return r_plain.status_code, r_notask.status_code


async def _variant1_proposed(
    client: httpx.AsyncClient,
    sender: SecurePushNotificationSender,
    attack_task_id: str,
) -> int:
    """변형 1 — 제안 수신자(/webhook) 대상.

    JWT.task_id ∉ {task-001} → 403 거부.
    """
    attack_task = make_task(attack_task_id, text='variant1 attack')
    attack_payload = attack_task.model_dump(mode='json', exclude_none=True)
    attack_jwt = sender._make_jwt(attack_task, f'{BASE_URL}/webhook')

    r = await client.post(
        f'{BASE_URL}/webhook',
        json=attack_payload,
        headers={'Authorization': f'Bearer {attack_jwt}'},
    )
    return r.status_code


async def _variant2_existing(
    client: httpx.AsyncClient,
    sender: SecurePushNotificationSender,
    forged_task_id: str,
) -> int:
    """변형 2 — 기존 수신자(/webhook-jwt-notask) 대상.

    합법 JWT(task-001) + 위조 payload(forged_task_id) 전송.
    교차검증 없음 → 수락.
    """
    legit_task = make_task(SUBSCRIBED_TASK)
    legit_jwt = sender._make_jwt(legit_task, f'{BASE_URL}/webhook')
    forged_payload = make_task(forged_task_id).model_dump(
        mode='json', exclude_none=True
    )

    r = await client.post(
        f'{BASE_URL}/webhook-jwt-notask',
        json=forged_payload,
        headers={'Authorization': f'Bearer {legit_jwt}'},
    )
    return r.status_code


async def _variant2_proposed(
    client: httpx.AsyncClient,
    sender: SecurePushNotificationSender,
    forged_task_id: str,
) -> int:
    """변형 2 — 제안 수신자(/webhook) 대상.

    JWT.task_id(task-001) ≠ payload.id(forged_task_id) → 403 거부.
    """
    legit_task = make_task(SUBSCRIBED_TASK)
    legit_jwt = sender._make_jwt(legit_task, f'{BASE_URL}/webhook')
    forged_payload = make_task(forged_task_id).model_dump(
        mode='json', exclude_none=True
    )

    r = await client.post(
        f'{BASE_URL}/webhook',
        json=forged_payload,
        headers={'Authorization': f'Bearer {legit_jwt}'},
    )
    return r.status_code


# ── 메인 실험 ────────────────────────────────────────────────────────────────


async def run() -> None:
    if not SECRET:
        print('❌ A2A_PUSH_JWT_SECRET 환경변수가 없습니다.')
        return
    if SUBSCRIBED_TASK not in os.getenv('A2A_PUSH_SUBSCRIBED_TASKS', ''):
        print(
            '❌ A2A_PUSH_SUBSCRIBED_TASKS 환경변수에 task-001이 포함되어야 합니다.\n'
            '   예) export A2A_PUSH_SUBSCRIBED_TASKS=task-001'
        )
        return

    total_attacks = len(ATTACK_TASKS) * N_REPEAT  # 공격 태스크 3종 × N회

    # 수신자별 · 변형별 카운터
    v1_plain = AcceptCounter(total_attacks)  # 변형1 — 기존(/webhook-plain)
    v1_notask = AcceptCounter(
        total_attacks
    )  # 변형1 — 기존(/webhook-jwt-notask)
    v1_secure = AcceptCounter(total_attacks)  # 변형1 — 제안(/webhook)
    v2_notask = AcceptCounter(
        total_attacks
    )  # 변형2 — 기존(/webhook-jwt-notask)
    v2_secure = AcceptCounter(total_attacks)  # 변형2 — 제안(/webhook)

    print('=' * 65)
    print('공격 수락률 비교 실험 - 기존 SDK vs 제안 방식')
    print(f'구독 태스크: {SUBSCRIBED_TASK}  |  공격 태스크: {ATTACK_TASKS}')
    print(
        f'반복 횟수: {N_REPEAT}회 × {len(ATTACK_TASKS)}종 = 총 {total_attacks}회/셀'
    )
    print('=' * 65)

    async with httpx.AsyncClient() as client:
        sender = _make_attack_sender(client)

        for attack_id in ATTACK_TASKS:
            for _ in range(N_REPEAT):
                # 변형 1
                sc_plain, sc_notask = await _variant1_existing(
                    client, sender, attack_id
                )
                v1_plain.record(sc_plain)
                v1_notask.record(sc_notask)
                sc_v1_secure = await _variant1_proposed(
                    client, sender, attack_id
                )
                v1_secure.record(sc_v1_secure)

                # 변형 2
                sc_v2_notask = await _variant2_existing(
                    client, sender, attack_id
                )
                v2_notask.record(sc_v2_notask)
                sc_v2_secure = await _variant2_proposed(
                    client, sender, attack_id
                )
                v2_secure.record(sc_v2_secure)

    # ── 결과 출력 ─────────────────────────────────────────────────────────────
    print()
    print(f'{"수신자 구현":<30} {"변형 1 수락률":>14} {"변형 2 수락률":>14}')
    print('-' * 60)
    print(
        f'{"기존(인증없음) /webhook-plain":<32} {v1_plain.summary():>14} {"N/A":>14}'
    )
    print(
        f'{"기존(JWT서명만) /webhook-jwt-notask":<32} {v1_notask.summary():>14} {v2_notask.summary():>14}'
    )
    print(
        f'{"제안(6단계) /webhook":<32} {v1_secure.summary():>14} {v2_secure.summary():>14}'
    )
    print('=' * 65)

    # 논문용 1-line 결론
    existing_v1 = max(v1_plain.accept_rate, v1_notask.accept_rate)
    existing_v2 = v2_notask.accept_rate
    proposed_v1 = v1_secure.accept_rate
    proposed_v2 = v2_secure.accept_rate

    print()
    print('[ 논문 결론 ]')
    print(
        f'  기존 SDK 수락률: 변형1={existing_v1:.0f}%  변형2={existing_v2:.0f}%'
    )
    print(
        f'  제안 방식 수락률: 변형1={proposed_v1:.0f}%  변형2={proposed_v2:.0f}%'
    )

    all_blocked = proposed_v1 == 0.0 and proposed_v2 == 0.0
    all_accepted = existing_v1 == 100.0 and existing_v2 == 100.0
    if all_blocked and all_accepted:
        print()
        print('[OK] 기존 100% 수락 / 제안 0% 수락 - 논문 주장 실험 검증 완료')
    else:
        print()
        print('[!!] 일부 결과가 예측과 다름 - 서버 환경 설정 확인 필요')
    print('=' * 65)


if __name__ == '__main__':
    asyncio.run(run())
