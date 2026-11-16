import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, EmailStr
from app.config import ALLOWED_ORIGINS, KEYS_DIR, KEY_PASSWORD, STORAGE_DIR
from app.middleware.security import SecurityMiddleware
from app.services import database
from app.services.crypto_vault import decrypt, encrypt
from app.services.digital_signature import generate_keypair, sign, verify
from app.services.jwt_service import decode_token, issue_pair
from app.services.passwords import hash_password, validate_password, verify_password
from app.services.sanitizer import sanitize_comment

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

@asynccontextmanager
async def lifespan(app: FastAPI):
    database.initialize()
    yield

app = FastAPI(title="Secure DocVault API", version="0.6", lifespan=lifespan)
app.add_middleware(SecurityMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True,
                   allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])

class RegisterPayload(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginPayload(BaseModel):
    username: str
    password: str

class RefreshPayload(BaseModel):
    refresh_token: str

def current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Відсутній Bearer токен")
    claims = decode_token(authorization.removeprefix("Bearer "), "access")
    user = database.get_user_by_username(claims["username"])
    if not user or not user["is_active"]:
        raise HTTPException(status_code=401, detail="Користувача не знайдено або вимкнено")
    return user

@app.get("/health")
def health(): return {"status": "ok"}

@app.post("/api/v1/auth/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterPayload):
    errors = validate_password(payload.password)
    if errors: raise HTTPException(status_code=400, detail=errors)
    identifier = database.create_user(payload.username, payload.email, hash_password(payload.password))
    if identifier is None: raise HTTPException(status_code=409, detail="Ім'я або email уже існує")
    return {"id": identifier, "message": "Користувача зареєстровано"}

@app.post("/api/v1/auth/login")
def login(payload: LoginPayload):
    user = database.get_user_by_username(payload.username)
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Невірне ім'я або пароль")
    return issue_pair(user)

@app.post("/api/v1/auth/refresh")
def refresh(payload: RefreshPayload):
    claims = decode_token(payload.refresh_token, "refresh")
    database.revoke_token(claims["jti"], claims["exp"])
    user = database.get_user_by_username(claims["username"])
    if not user: raise HTTPException(status_code=401, detail="Користувача не знайдено")
    return issue_pair(user)

@app.get("/api/v1/user/profile")
def profile(user=Depends(current_user)):
    return {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]}

@app.post("/api/v1/comments")
def comment(text: str = Form(...), user=Depends(current_user)):
    return {"author": user["username"], "text": sanitize_comment(text)}

def user_key(user_id: int):
    pem_path = KEYS_DIR / f"user-{user_id}-private.pem"
    if not pem_path.exists():
        private, private_pem, public_pem = generate_keypair(KEY_PASSWORD)
        pem_path.write_bytes(private_pem)
        (KEYS_DIR / f"user-{user_id}-public.pem").write_bytes(public_pem)
        return private, public_pem
    from cryptography.hazmat.primitives import serialization
    private = serialization.load_pem_private_key(pem_path.read_bytes(), password=KEY_PASSWORD)
    return private, (KEYS_DIR / f"user-{user_id}-public.pem").read_bytes()

@app.post("/api/v1/documents/upload", status_code=201)
async def upload(file: UploadFile = File(...), user=Depends(current_user)):
    raw = await file.read()
    if not raw: raise HTTPException(status_code=400, detail="Порожній файл")
    document_id, storage_name = str(uuid4()), f"{uuid4()}.bin"
    private, public_pem = user_key(user["id"])
    (STORAGE_DIR / storage_name).write_bytes(encrypt(raw))
    database.save_document(document_id, user["id"], Path(file.filename or "document").name, storage_name,
                           file.content_type or "application/octet-stream", sign(raw, private), public_pem,
                           datetime.now(timezone.utc).isoformat())
    return {"id": document_id, "status": "Encrypted, Signed & Verified"}

@app.get("/api/v1/documents/{document_id}/download")
def download(document_id: str, user=Depends(current_user)):
    record = database.get_document(document_id)
    if not record or record["owner_id"] != user["id"]: raise HTTPException(status_code=404, detail="Документ не знайдено")
    try: raw = decrypt((STORAGE_DIR / record["storage_name"]).read_bytes())
    except Exception as exc: raise HTTPException(status_code=409, detail="Контейнер пошкоджений: видачу заблоковано") from exc
    if not verify(raw, record["signature"], record["signer_public_key"]):
        raise HTTPException(status_code=409, detail="Підпис не пройшов перевірку")
    return Response(raw, media_type=record["content_type"], headers={"Content-Disposition": f'attachment; filename="{record["original_name"]}"', "X-Signature-Status": "Signed & Verified"})
