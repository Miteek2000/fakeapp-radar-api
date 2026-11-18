"""Dependencias de FastAPI: quién es el usuario que hace la petición."""
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth import service, tokens
from app.config import allowed_origins_list

bearer = HTTPBearer(auto_error=False, description="Token de acceso que devuelve /auth/login")

UNAUTHORIZED = {"WWW-Authenticate": "Bearer"}


def _user_from(creds: HTTPAuthorizationCredentials) -> service.UserView:
    try:
        user_id = tokens.decode_access_token(creds.credentials)
    except tokens.AuthNotConfigured:
        raise HTTPException(status_code=503, detail="La autenticación no está configurada")
    except tokens.InvalidToken:
        raise HTTPException(status_code=401, detail="Tu sesión venció. Inicia sesión de nuevo.", headers=UNAUTHORIZED)
    user = service.get_active_user(user_id)
    if user is None:  # cuenta borrada o desactivada: el token deja de servir al instante
        raise HTTPException(status_code=401, detail="Tu sesión venció. Inicia sesión de nuevo.", headers=UNAUTHORIZED)
    return user


def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> service.UserView:
    if creds is None:
        raise HTTPException(status_code=401, detail="Inicia sesión para continuar.", headers=UNAUTHORIZED)
    return _user_from(creds)


def optional_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> service.UserView | None:
    """Sin token = anónimo. Con un token inválido NO se trata como anónimo: se rechaza."""
    if creds is None:
        return None
    return _user_from(creds)


def require_trusted_origin(request: Request) -> None:
    """Defensa CSRF para las rutas que usan la cookie: si el navegador declara un origen, debe ser uno nuestro.
    Un ataque desde otra página siempre manda su Origin; un cliente sin navegador (curl) no manda ninguno."""
    origin = request.headers.get("origin")
    if origin is not None and origin not in allowed_origins_list():
        raise HTTPException(status_code=403, detail="Origen no permitido")
