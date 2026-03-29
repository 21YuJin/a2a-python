import jwt, uuid, time, json

secret = 'test-secret'
now = int(time.time())
payload = {
    'iss': 'agentB',
    'aud': 'agentA-webhook',
    'iat': now,
    'exp': now + 60,
    'jti': str(uuid.uuid4()),
    'task_id': 'task-001'
}
token = jwt.encode(payload, secret, algorithm='HS256')
print('=== JWT Token ===')
print(token)
print()
decoded = jwt.decode(token, secret, algorithms=['HS256'], audience='agentA-webhook')
print('=== Decoded Claims ===')
print(json.dumps(decoded, indent=2))
