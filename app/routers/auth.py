import logging

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel

from app.auth import service, tokens
from app.auth.deps import current_user, require_trusted_origin
from app.config import settings
from app.ratelimit import limiter

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

COOKIE = "refresh_token"
NO_STORE = {"Cache-Control": "no-store"}


class Credentials(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    id: str
    email: str
    created_at: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


def _user_out(u: service.UserView) -> UserOut:
    return UserOut(id=str(u.id), email=u.email, created_at=u.created_at.isoformat())


def _set_cookie(response: Response, value: str) -> None:
    response.set_cookie(
        COOKIE,
        value,
        max_age=settings.refresh_token_days * 86400,
        httponly=True,  # JavaScript no puede leerla
        secure=settings.cookie_secure,
        samesite="strict",
        path=settings.refresh_cookie_path,
    )


def _clear_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE, path=settings.refresh_cookie_path, httponly=True, secure=settings.cookie_secure, samesite="strict")


def _token_out(session: service.Session) -> TokenOut:
    return TokenOut(
        access_token=session.access_token,
        expires_in=settings.access_token_minutes * 60,
        user=_user_out(session.user),
    )


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
@limiter.limit(lambda: settings.rate_register)
def register(request: Request, response: Response, body: Credentials):
    email = service.normalize_email(body.email)
    problem = service.validate_email(email) or service.validate_password(body.password, email)
    if problem:
        raise HTTPException(status_code=422, detail=problem)
    try:
        user = service.register(email, body.password)
    except service.EmailTaken:
        raise HTTPException(status_code=409, detail="Ese correo ya tiene una cuenta")
    response.headers.update(NO_STORE)
    return _user_out(user)


@router.post("/login", response_model=TokenOut)
@limiter.limit(lambda: settings.rate_login)
def login(request: Request, response: Response, body: Credentials):
    try:
        session = service.login(service.normalize_email(body.email), body.password)
    except service.InvalidCredentials:
        # Mismo mensaje para "no existe" y "contraseña incorrecta": no delatamos qué correos están registrados.
        raise HTTPException(status_code=401, detail="Correo o contraseña incorrectos")
    except tokens.AuthNotConfigured:
        log.error("Falta configurar JWT_PRIVATE_KEY_B64")
        raise HTTPException(status_code=503, detail="La autenticación no está configurada")
    _set_cookie(response, session.refresh_token)
    response.headers.update(NO_STORE)
    return _token_out(session)


@router.post("/refresh", response_model=TokenOut, dependencies=[Depends(require_trusted_origin)])
@limiter.limit(lambda: settings.rate_refresh)
def refresh(request: Request, response: Response, refresh_token: str | None = Cookie(default=None)):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No hay una sesión activa")
    try:
        session = service.refresh(refresh_token)
    except service.RefreshInProgress:
        # No tocamos la cookie: la otra petición ya está renovando la sesión.
        raise HTTPException(status_code=409, detail="La sesión se está renovando, inténtalo de nuevo")
    except service.InvalidRefresh:
        _clear_cookie(response)
        raise HTTPException(status_code=401, detail="Tu sesión venció. Inicia sesión de nuevo.")
    except tokens.AuthNotConfigured:
        raise HTTPException(status_code=503, detail="La autenticación no está configurada")
    _set_cookie(response, session.refresh_token)
    response.headers.update(NO_STORE)
    return _token_out(session)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_trusted_origin)])
def logout(response: Response, refresh_token: str | None = Cookie(default=None)):
    service.logout(refresh_token)
    _clear_cookie(response)
    response.headers.update(NO_STORE)


@router.get("/me", response_model=UserOut)
def me(user: service.UserView = Depends(current_user)):
    return _user_out(user)
