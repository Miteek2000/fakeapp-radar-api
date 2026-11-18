"""Reglas de cuentas y sesiones. Todo lo que toca la base de datos vive aquí."""
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from app.auth import passwords, tokens
from app.config import settings
from app.db import session_scope
from app.models import RefreshToken, User

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class EmailTaken(Exception):
    pass


class InvalidCredentials(Exception):
    pass


class InvalidRefresh(Exception):
    """Refresh inválido, vencido, revocado o reutilizado."""


class RefreshInProgress(Exception):
    """El mismo refresh se usó hace instantes (dos pestañas a la vez). No es un robo: se pide reintentar."""


@dataclass(frozen=True)
class UserView:
    id: uuid.UUID
    email: str
    created_at: datetime


@dataclass(frozen=True)
class Session:
    user: UserView
    access_token: str
    refresh_token: str


def normalize_email(email: str) -> str:
    return email.strip().lower()


def validate_email(email: str) -> str | None:
    """Devuelve un mensaje de error o None si está bien."""
    if len(email) > 254 or not EMAIL_RE.match(email):
        return "Escribe un correo válido"
    return None


def validate_password(password: str, email: str) -> str | None:
    if len(password) < passwords.MIN_LENGTH:
        return f"La contraseña debe tener al menos {passwords.MIN_LENGTH} caracteres"
    if len(password) > passwords.MAX_LENGTH:
        return f"La contraseña no puede pasar de {passwords.MAX_LENGTH} caracteres"
    if password.strip().lower() == email or password.strip().lower() == email.split("@")[0]:
        return "La contraseña no puede ser igual a tu correo"
    return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _view(u: User) -> UserView:
    return UserView(id=u.id, email=u.email, created_at=u.created_at)


def register(email: str, password: str) -> UserView:
    try:
        with session_scope() as s:
            user = User(email=email, password_hash=passwords.hash_password(password))
            s.add(user)
            s.flush()
            return _view(user)
    except IntegrityError as exc:
        raise EmailTaken() from exc


def _issue_refresh(session, user_id: uuid.UUID, family_id: uuid.UUID) -> str:
    raw = tokens.new_refresh_token()
    session.add(
        RefreshToken(
            user_id=user_id,
            family_id=family_id,
            token_hash=tokens.hash_refresh_token(raw),
            expires_at=_now() + timedelta(days=settings.refresh_token_days),
        )
    )
    return raw


def login(email: str, password: str) -> Session:
    with session_scope() as s:
        user = s.scalar(select(User).where(User.email == email))
        ok = passwords.verify_password(user.password_hash if user else None, password)
        if not ok or user is None or not user.is_active:
            raise InvalidCredentials()
        if passwords.needs_rehash(user.password_hash):
            user.password_hash = passwords.hash_password(password)
        refresh = _issue_refresh(s, user.id, uuid.uuid4())
        return Session(_view(user), tokens.create_access_token(user.id), refresh)


def refresh(raw_token: str) -> Session:
    """Rota el refresh: el anterior queda revocado y se entrega uno nuevo de la misma familia.

    Si llega un refresh que ya fue usado, puede ser un robo: se revoca TODA la familia (cierra esa sesión).
    """
    token_hash = tokens.hash_refresh_token(raw_token)
    with session_scope() as s:
        row = s.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
        if row is None:
            raise InvalidRefresh()
        now = _now()

        if row.revoked_at is not None:
            # La tolerancia solo aplica si el token se cambió por rotación hace instantes (dos pestañas a la vez).
            # Si se revocó por cierre de sesión o por robo, no hay tolerancia.
            if row.rotated and now - _aware(row.revoked_at) <= timedelta(seconds=settings.refresh_reuse_grace_seconds):
                raise RefreshInProgress()
            s.execute(
                update(RefreshToken)
                .where(RefreshToken.family_id == row.family_id, RefreshToken.revoked_at.is_(None))
                .values(revoked_at=now)
            )
            s.commit()  # el cierre de la familia debe quedar guardado aunque aquí lancemos el error
            raise InvalidRefresh()

        if _aware(row.expires_at) <= now:
            raise InvalidRefresh()

        user = s.get(User, row.user_id)
        if user is None or not user.is_active:
            raise InvalidRefresh()

        # Revocación atómica: si dos peticiones llegan a la vez, solo una gana.
        won = s.execute(
            update(RefreshToken)
            .where(RefreshToken.id == row.id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now, rotated=True)
        ).rowcount
        if won != 1:
            raise RefreshInProgress()
        new_raw = _issue_refresh(s, user.id, row.family_id)
        return Session(_view(user), tokens.create_access_token(user.id), new_raw)


def logout(raw_token: str | None) -> None:
    """Cierra la sesión (toda la familia del refresh). Si el token no existe, no pasa nada."""
    if not raw_token:
        return
    token_hash = tokens.hash_refresh_token(raw_token)
    with session_scope() as s:
        row = s.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
        if row is not None:
            s.execute(
                update(RefreshToken)
                .where(RefreshToken.family_id == row.family_id, RefreshToken.revoked_at.is_(None))
                .values(revoked_at=_now())
            )


def get_active_user(user_id: uuid.UUID) -> UserView | None:
    with session_scope() as s:
        user = s.get(User, user_id)
        return _view(user) if user is not None and user.is_active else None


def purge_old_refresh_tokens() -> int:
    """Borra los refresh vencidos hace más de un día (retención)."""
    cutoff = _now() - timedelta(days=1)
    with session_scope() as s:
        return s.execute(delete(RefreshToken).where(RefreshToken.expires_at < cutoff)).rowcount or 0
