import base64
import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
STORAGE_DIR = ROOT / "storage"
KEYS_DIR = ROOT / "keys"
DB_PATH = DATA_DIR / "docvault.db"

for directory in (DATA_DIR, STORAGE_DIR, KEYS_DIR):
    directory.mkdir(exist_ok=True)

# Development-safe defaults make the laboratory executable. Deployment must set
# these values in the environment and keep them out of source control.
JWT_SECRET = os.getenv("JWT_SECRET", "development-only-change-this-secret-32chars")
FILE_KEY_B64 = os.getenv("FILE_ENCRYPTION_KEY")
FILE_KEY = base64.urlsafe_b64decode(FILE_KEY_B64) if FILE_KEY_B64 else secrets.token_bytes(32)
KEY_PASSWORD = os.getenv("KEY_ENCRYPTION_PASSWORD", "development-key-export-password").encode()
ALLOWED_ORIGINS = [item.strip() for item in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")]
