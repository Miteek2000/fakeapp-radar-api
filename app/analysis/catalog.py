"""Catálogo de permisos de Android explicados en español.

Vive en la tabla `permission_catalog` (repo fakeapp-radar-db). Aquí solo se lee.
"""
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import PermissionCatalog


@dataclass(frozen=True)
class CatalogEntry:
    android_name: str
    friendly_title: str
    explanation: str
    severity: str  # peligroso | atencion | normal
    weight: int
    icon: str


Catalog = dict[str, CatalogEntry]


class EmptyCatalogError(RuntimeError):
    """La tabla está vacía: sin catálogo todos los permisos saldrían como "desconocidos"."""


def load_catalog(session: Session) -> Catalog:
    rows = session.scalars(select(PermissionCatalog)).all()
    if not rows:
        raise EmptyCatalogError(
            "La tabla permission_catalog está vacía. Levanta el repo fakeapp-radar-db (carga el catálogo)."
        )
    return {
        r.android_name: CatalogEntry(r.android_name, r.friendly_title, r.explanation, r.severity, r.weight, r.icon)
        for r in rows
    }
