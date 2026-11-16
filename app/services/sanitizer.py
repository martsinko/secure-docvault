import bleach


def sanitize_comment(value: str) -> str:
    """Store plain text only; script tags and event handlers never reach a browser."""
    return bleach.clean(value, tags=[], attributes={}, strip=True)
