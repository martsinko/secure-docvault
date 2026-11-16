import re

# A deliberately small signature WAF is defense in depth, not a replacement
# for parameterized SQL, input validation, patching and application controls.
PATTERNS = [
    r"\.\.[\\/]", r"<\s*script", r"on\w+\s*=", r"union\s+select", r"\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1",
    r"\b(drop|alter)\s+table", r"/etc/passwd",
]
COMPILED = [re.compile(pattern, re.IGNORECASE) for pattern in PATTERNS]


def is_malicious(value: str) -> bool:
    return any(pattern.search(value) for pattern in COMPILED)
