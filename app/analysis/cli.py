import sys

from app.analysis.analyzer import InvalidApkError, analyze_apk


def main() -> int:
    if len(sys.argv) != 2:
        print("Uso: python -m app.analysis.cli archivo.apk")
        return 2
    sys.stdout.reconfigure(encoding="utf-8")
    try:
        report = analyze_apk(sys.argv[1])
    except InvalidApkError as exc:
        print(f"APK inválido: {exc}")
        return 1
    print(report.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
