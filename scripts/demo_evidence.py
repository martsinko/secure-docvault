"""Run a non-destructive local demonstration against Secure DocVault."""
import json
import sys
import uuid
from pathlib import Path
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.services.crypto_vault import decrypt, encrypt, InvalidTag
from app.services.digital_signature import generate_keypair, sign, verify

BASE = "http://127.0.0.1:8000"
name = f"nazar_demo_{uuid.uuid4().hex[:8]}"

def show(label, response):
    print(f"\n=== {label} ===")
    print(f"HTTP {response.status_code}")
    for key in ("content-security-policy", "x-frame-options", "retry-after", "x-signature-status"):
        if key in response.headers: print(f"{key}: {response.headers[key]}")
    try:
        data = response.json()
        for sensitive in ("access_token", "refresh_token"):
            if sensitive in data: data[sensitive] = data[sensitive][:28] + "..."
        print(json.dumps(data, ensure_ascii=False, indent=2))
    except Exception:
        print(response.text[:300])

with httpx.Client() as client:
    show("Security headers", client.get(f"{BASE}/health"))
    show("Registration", client.post(f"{BASE}/api/v1/auth/register", json={"username": name, "email": f"{name}@example.com", "password": "StrongPass1!"}))
    login = client.post(f"{BASE}/api/v1/auth/login", json={"username": name, "password": "StrongPass1!"})
    show("JWT login", login)
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    show("Protected profile", client.get(f"{BASE}/api/v1/user/profile", headers=headers))
    upload = client.post(f"{BASE}/api/v1/documents/upload", headers=headers, files={"file": ("confidential.txt", b"CONFIDENTIAL SECURE DOCVAULT REPORT", "text/plain")})
    show("Encrypted and signed upload", upload)
    doc_id = upload.json()["id"]
    show("Signed verified download", client.get(f"{BASE}/api/v1/documents/{doc_id}/download", headers=headers))
    show("WAF blocks traversal", client.get(f"{BASE}/../etc/passwd"))

print("\n=== AES-256-GCM integrity ===")
blob = bytearray(encrypt(b"CONFIDENTIAL")); blob[20] ^= 0xFF
try: decrypt(bytes(blob))
except InvalidTag: print("InvalidTag: modification detected; decrypted content blocked")

print("\n=== RSA-PSS signature integrity ===")
private, _, public = generate_keypair(b"demo-key-password")
signature = sign(b"approved", private)
print("valid document:", verify(b"approved", signature, public))
print("tampered document:", verify(b"rejected", signature, public))
