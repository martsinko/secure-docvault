from datetime import datetime, timedelta, timezone
from uuid import uuid4
import jwt
from fastapi import HTTPException, status
from app.config import JWT_SECRET
from app.services.database import is_revoked

ALGORITHM = "HS256"


def issue_token(user, kind: str, minutes: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user["id"]), "username": user["username"], "role": user["role"],
               "type": kind, "jti": str(uuid4()), "iat": now, "exp": now + timedelta(minutes=minutes)}
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def issue_pair(user) -> dict[str, str]:
    return {"access_token": issue_token(user, "access", 15), "refresh_token": issue_token(user, "refresh", 60 * 24 * 7), "token_type": "bearer"}


def decode_token(token: str, expected_type: str) -> dict:
    try:
        # Explicit algorithm allow-list prevents alg:none and confusion attacks.
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM], options={"require": ["exp", "sub", "jti", "type"]})
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Недійсний або прострочений токен") from exc
    if payload["type"] != expected_type or is_revoked(payload["jti"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Токен відкликано або використано не за призначенням")
    return payload
