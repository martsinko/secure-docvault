import bcrypt
import re


def validate_password(password: str) -> list[str]:
    checks = [
        (len(password) >= 8, "Пароль має містити щонайменше 8 символів"),
        (bool(re.search(r"[A-Z]", password)), "Пароль має містити велику літеру"),
        (bool(re.search(r"[a-z]", password)), "Пароль має містити малу літеру"),
        (bool(re.search(r"\d", password)), "Пароль має містити цифру"),
        (bool(re.search(r"[^\w\s]", password)), "Пароль має містити спеціальний символ"),
    ]
    return [message for valid, message in checks if not valid]


def hash_password(password: str) -> str:
    """bcrypt embeds a unique salt in its encoded output; cost 12 slows brute force."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, encoded_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), encoded_hash.encode())
