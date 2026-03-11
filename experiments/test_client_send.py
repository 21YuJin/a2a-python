import asyncio
import json
import uuid

import httpx


SERVER_URL = 'http://127.0.0.1:9999/'  # A2A JSON-RPC endpoint
WEBHOOK_URL = 'http://127.0.0.1:8000/webhook'  # receiver


def build_payload(use_camel: bool):
    """
    use_camel=False -> snake_case fields (push_notification_config)
    use_camel=True  -> camelCase fields (pushNotificationConfig)
    둘 중 하나가 네 a2a-python types alias에 맞을 것.
    """
    message = {
        'message_id': str(uuid.uuid4()),
        'role': 'user',
        'parts': [{'kind': 'text', 'text': 'hi (trigger push)'}],
        # task_id/context_id는 생략해도 되고, 넣어도 됨.
    }

    push_cfg = {
        'id': 'cfg-1',
        'url': WEBHOOK_URL,
        # token은 baseline header용이라 지금은 None/생략
    }

    if use_camel:
        configuration = {
            'blocking': True,
            'pushNotificationConfig': push_cfg,
        }
    else:
        configuration = {
            'blocking': True,
            'push_notification_config': push_cfg,
        }

    params = {
        'message': message,
        'configuration': configuration,
    }

    return {
        'jsonrpc': '2.0',
        'id': str(uuid.uuid4()),
        'method': 'message/send',
        'params': params,
    }


async def main():
    async with httpx.AsyncClient(timeout=20.0) as client:
        # 1) snake_case로 먼저 시도
        for use_camel in (False, True):
            payload = build_payload(use_camel=use_camel)
            resp = await client.post(SERVER_URL, json=payload)
            print(
                '\n=== Tried:',
                'camelCase' if use_camel else 'snake_case',
                '===',
            )
            print('HTTP', resp.status_code)
            try:
                print(json.dumps(resp.json(), indent=2, ensure_ascii=False))
            except Exception:
                print(resp.text)

            # 성공했으면 더 이상 시도 안 함
            if resp.status_code == 200:
                # JSON-RPC error가 없는지도 확인
                j = resp.json()
                if 'error' not in j:
                    print('✅ message/send succeeded')
                    return

        print(
            '\n❌ Both snake_case and camelCase failed. Check server error response above.'
        )


if __name__ == '__main__':
    asyncio.run(main())
