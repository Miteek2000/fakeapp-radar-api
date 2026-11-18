# Comprueba que https://localhost solo acepta TLS 1.3. Uso:  .\security\tls.ps1
# 1) TLS 1.3 debe funcionar   2) TLS 1.2 debe ser rechazado   3) cabecera HSTS presente
Write-Host "TLS 1.3 (debe responder 200 o 30x):" -ForegroundColor Cyan
curl.exe -sk --tlsv1.3 -o NUL -w "  codigo HTTP: %{http_code}`n" https://localhost

Write-Host "TLS 1.2 (debe FALLAR):" -ForegroundColor Cyan
curl.exe -sk --tlsv1.2 --tls-max 1.2 -o NUL -w "  codigo HTTP: %{http_code}`n" https://localhost
if ($LASTEXITCODE -ne 0) { Write-Host "  rechazado, correcto (curl salio con codigo $LASTEXITCODE)" -ForegroundColor Green }
else { Write-Host "  ATENCION: acepto TLS 1.2" -ForegroundColor Red }

Write-Host "Cabeceras de seguridad:" -ForegroundColor Cyan
curl.exe -skI https://localhost | Select-String -Pattern "strict-transport|x-content-type|x-frame|referrer"
