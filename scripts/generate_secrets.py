import base64, secrets
print("JWT_SECRET=" + secrets.token_urlsafe(48))
print("FILE_ENCRYPTION_KEY=" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
print("KEY_ENCRYPTION_PASSWORD=" + secrets.token_urlsafe(32))
