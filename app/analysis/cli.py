"""Analiza un APK desde la terminal:  python -m app.analysis.cli archivo.apk
(lee el catálogo de la base: necesita DATABASE_URL, por ejemplo en tu .env)"""
import sys

from app.analysis.analyzer import InvalidApkError, analyze_apk
from app.analysis.catalog import load_catalog
from app.db import session_scope


def main() -> int:
    if len(sys.argv) != 2:
        print("Uso: python -m app.analysis.cli archivo.apk")
        return 2
    sys.stdout.reconfigure(encoding="utf-8")
    with session_scope() as session:
        catalog = load_catalog(session)
    try:
        report = analyze_apk(sys.argv[1], catalog)
    except InvalidApkError as exc:
        print(f"APK inválido: {exc}")
        return 1
    print(report.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
