# Escaneo de la API con OWASP ZAP (baseline sobre el esquema OpenAPI).
# Requiere la API arriba (db repo primero, luego este). Uso:  .\security\zap.ps1
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path security/reports | Out-Null
docker run --rm -v "${PWD}/security/reports:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable `
    zap-api-scan.py -t http://host.docker.internal:8000/openapi.json -f openapi `
    -r zap_report.html -w zap_report.md -I
