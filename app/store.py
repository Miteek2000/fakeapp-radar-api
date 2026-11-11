"""Estado y resultado de cada análisis, guardados en Redis.

Es temporal: cada registro se borra solo a las 24 horas. En la fase 5 el
resultado definitivo pasa a PostgreSQL (cifrado) y esto queda solo como estado.
"""
import json
from typing import Any
from uuid import UUID

import redis

from app.config import settings

_client: redis.Redis | None = None


def get_client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    return _client


def _key(analysis_id: str | UUID) -> str:
    return f"analysis:{analysis_id}"


def save(analysis_id: str | UUID, status, report: dict | None = None, error: str | None = None) -> None:
    data = {
        "id": str(analysis_id),
        "status": getattr(status, "value", status),
        "report": report,
        "error": error,
    }
    get_client().set(_key(analysis_id), json.dumps(data), ex=settings.result_ttl_seconds)


def load(analysis_id: str | UUID) -> dict[str, Any] | None:
    raw = get_client().get(_key(analysis_id))
    return json.loads(raw) if raw else None
