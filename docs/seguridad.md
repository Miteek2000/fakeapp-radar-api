# Seguridad: análisis y resultados (fase 11)

| Herramienta | Qué revisa | Resultado |
|---|---|---|
| Bandit 1.9.4 | Código Python del API (`app/`, 1267 líneas) | 4 hallazgos → corregidos, 0 pendientes |
| pip-audit | Dependencias de `requirements-docker.txt` | Sin vulnerabilidades conocidas |
| npm audit | Dependencias de producción del front | 0 vulnerabilidades |
| Trivy | Imágenes Docker (HIGH/CRITICAL con arreglo) | `.\security\trivy.ps1` → ver `security/reports/` |
| OWASP ZAP | API en ejecución (OpenAPI, 44 URLs) | 118 pruebas pasan, 0 fallos, 2 avisos → corregidos con cabeceras de seguridad |

## Bandit: hallazgos y decisión

| Regla | Dónde | Decisión |
|---|---|---|
| B324 MD5 / SHA-1 | `analysis/analyzer.py` | Solo se muestran como dato de referencia; marcado `usedforsecurity=False`. La identidad del archivo es el SHA-256. |
| B101 assert | `db.py` | Cambiado por una excepción explícita (un `assert` desaparece con `python -O`). |
| B310 urlopen | `vt/client.py` | URL fija `https://` y SHA-256 validado como 64 hex; se documenta con `# nosec B310`. |

## ZAP: avisos y decisión

| Aviso | Corrección |
|---|---|
| X-Content-Type-Options ausente (`/health`, `/openapi.json`) | Cabecera `nosniff` en todas las respuestas (`app/main.py`) |
| Cross-Origin-Resource-Policy ausente | `same-origin` en todas las respuestas |

Además se agregaron `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` y `Cache-Control: no-store`. Hay una prueba automática (`test_cabeceras_de_seguridad_en_todas_las_respuestas`).
Pendiente de la fase 12: `Strict-Transport-Security` y TLS 1.3 se activan en el proxy con HTTPS, no en la API.

## Cómo repetirlo

```powershell
bandit -r app
pip-audit -r requirements-docker.txt
.\security\trivy.ps1
.\security\zap.ps1
```

Nota para ZAP: el límite de 5 peticiones por minuto (slowapi) hace que parte del escaneo reciba 429. Es el comportamiento esperado; si se quiere un barrido completo, se puede poner `RATE_LIMIT_ENABLED` en falso solo para esa corrida (nunca en producción).
