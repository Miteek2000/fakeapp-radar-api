from fastapi import FastAPI, Request
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.config import settings
from app.ratelimit import limiter, rate_limit_handler
from app.routers import analyses, auth, health

app = FastAPI(title=settings.app_name, version="0.1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
app.add_middleware(SlowAPIMiddleware)

# Cabeceras de seguridad en TODAS las respuestas (recomendadas por OWASP ZAP).
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",  # el navegador no "adivina" el tipo de archivo
    "Cross-Origin-Resource-Policy": "same-origin",  # otros sitios no pueden incrustar respuestas de la API
    "X-Frame-Options": "DENY",  # no se puede meter la API en un iframe (clickjacking)
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",  # respuestas con datos de cuenta o análisis: que no queden en caché
}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


app.include_router(health.router)
app.include_router(auth.router)
app.include_router(analyses.router)
