from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from app.config import ALLOWED_ORIGINS
from app.middleware.waf_filter import is_malicious
from app.middleware.rate_limiter import limiter


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        if limiter.is_blocked(client_ip):
            return JSONResponse({"detail": "IP тимчасово заблоковано WAF"}, status_code=403)
        if not limiter.allow(client_ip):
            response = JSONResponse({"detail": "Ліміт запитів перевищено"}, status_code=429)
            response.headers["Retry-After"] = str(limiter.retry_after(client_ip))
            return add_headers(response)
        body = await request.body()
        candidate = " ".join([request.url.path, request.url.query, body.decode("utf-8", "ignore")])
        if is_malicious(candidate):
            limiter.greylist(client_ip)
            return add_headers(JSONResponse({"detail": "Запит заблоковано WAF"}, status_code=403))
        response = await call_next(request)
        return add_headers(response)


def add_headers(response):
    response.headers.update({
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    })
    return response
