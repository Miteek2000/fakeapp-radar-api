"""Vigila el aislamiento y el endurecimiento del docker-compose.yml (no necesita Docker)."""
from pathlib import Path

import pytest
import yaml

COMPOSE = yaml.safe_load((Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text(encoding="utf-8"))
SERVICIOS = COMPOSE["services"]
REDES = COMPOSE["networks"]


def redes_de(nombre: str) -> list[str]:
    return list(SERVICIOS[nombre]["networks"])


def con_salida(red: str) -> bool:
    """Una red tiene salida a internet si NO es interna y no es la externa del repo -db (que sí es interna)."""
    return not REDES[red].get("internal", False) and not REDES[red].get("external", False)


@pytest.mark.parametrize("servicio", ["worker", "beat", "redis"])
def test_servicios_internos_no_tienen_red_con_salida(servicio):
    assert not [r for r in redes_de(servicio) if con_salida(r)]


def test_solo_la_api_publica_puertos_y_solo_en_localhost():
    for nombre, s in SERVICIOS.items():
        if nombre == "api":
            assert s["ports"] == ["127.0.0.1:8000:8000"]
        else:
            assert "ports" not in s, f"{nombre} no debe publicar puertos"


def test_la_api_tiene_una_red_para_publicar_su_puerto():
    assert any(con_salida(r) for r in redes_de("api"))


def test_backend_es_interna_y_la_de_la_base_es_externa():
    assert REDES["backend"]["internal"] is True
    assert REDES["fakeapp-net"]["external"] is True


@pytest.mark.parametrize("servicio", list(SERVICIOS))
def test_contenedores_endurecidos(servicio):
    s = SERVICIOS[servicio]
    assert s["read_only"] is True
    assert s["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in s["security_opt"]
    assert s.get("mem_limit") and s.get("pids_limit")


def test_secretos_no_estan_escritos_en_el_compose():
    texto = (Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text(encoding="utf-8")
    assert "ENCRYPTION_KEY: ${ENCRYPTION_KEY:?" in texto and "REDIS_PASSWORD:?" in texto
