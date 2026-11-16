from fastapi.testclient import TestClient
from cryptography.exceptions import InvalidTag
from app.main import app
from app.services import database
from app.services.crypto_vault import decrypt, encrypt
from app.services.digital_signature import generate_keypair, sign, verify
from app.middleware.rate_limiter import limiter


client = TestClient(app)
database.initialize()

def unique(name):
    import uuid
    return f"{name}{uuid.uuid4().hex[:8]}"

def authenticate():
    # Tests are independent; production limiter intentionally keeps per-IP state.
    limiter.requests.clear()
    limiter.blocked_until.clear()
    username = unique("student")
    response = client.post("/api/v1/auth/register", json={"username": username, "email": f"{username}@example.com", "password": "StrongPass1!"})
    assert response.status_code == 201
    response = client.post("/api/v1/auth/login", json={"username": username, "password": "StrongPass1!"})
    assert response.status_code == 200
    return response.json()["access_token"], response.json()["refresh_token"]

def test_password_login_jwt_and_refresh_rotation():
    access, refresh = authenticate()
    assert client.get("/api/v1/user/profile", headers={"Authorization": f"Bearer {access}"}).status_code == 200
    assert client.get("/api/v1/user/profile").status_code == 401
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": refresh}).status_code == 200
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": refresh}).status_code == 401

def test_security_headers_sanitization_and_waf():
    health = client.get("/health")
    assert "frame-ancestors 'none'" in health.headers["content-security-policy"]
    access, _ = authenticate()
    comment = client.post("/api/v1/comments", data={"text": "hello <b>safe</b>"}, headers={"Authorization": f"Bearer {access}"})
    assert comment.json()["text"] == "hello safe"
    assert client.get("/../../etc/passwd").status_code in (403, 404)

def test_aes_gcm_detects_tampering():
    encrypted = bytearray(encrypt(b"CONFIDENTIAL"))
    assert decrypt(encrypted) == b"CONFIDENTIAL"
    encrypted[20] ^= 0xFF
    try: decrypt(bytes(encrypted))
    except InvalidTag: pass
    else: raise AssertionError("GCM tag did not reject tampering")

def test_rsa_pss_detects_tampering():
    private, _, public = generate_keypair(b"test-export-password")
    signature = sign(b"approved", private)
    assert verify(b"approved", signature, public)
    assert not verify(b"rejected", signature, public)

def test_encrypted_signed_document_round_trip():
    access, _ = authenticate()
    headers = {"Authorization": f"Bearer {access}"}
    upload = client.post("/api/v1/documents/upload", headers=headers,
                         files={"file": ("report.txt", b"CONFIDENTIAL REPORT", "text/plain")})
    assert upload.status_code == 201
    download = client.get(f"/api/v1/documents/{upload.json()['id']}/download", headers=headers)
    assert download.status_code == 200
    assert download.content == b"CONFIDENTIAL REPORT"
    assert download.headers["x-signature-status"] == "Signed & Verified"
