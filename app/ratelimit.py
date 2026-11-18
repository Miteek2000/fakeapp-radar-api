"""Límite de peticiones por IP (slowapi)."""
from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

from app.config import settings


def client_ip(request: Request) -> str:
    """IP del cliente. X-Forwarded-For solo se respeta si hay un proxy propio (TRUST_PROXY_HEADERS=true);
    si no, cualquiera podría escribir esa cabecera y saltarse el límite."""
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "desconocida"


limiter = Limiter(
    key_func=client_ip,
    default_limits=[lambda: settings.rate_default],
    storage_uri=settings.rate_limit_storage_uri,
    headers_enabled=True,
    in_memory_fallback_enabled=True,  # si Redis se cae, sigue limitando en memoria en vez de dejar pasar todo
    enabled=settings.rate_limit_enabled,
)


def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    response = JSONResponse(
        status_code=429,
        content={"detail": "Hiciste demasiadas solicitudes seguidas. Espera un momento e inténtalo de nuevo."},
    )
    return request.app.state.limiter._inject_headers(response, request.state.view_rate_limit)
