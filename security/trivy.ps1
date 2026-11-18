# Escanea con Trivy las imágenes del compose (HIGH y CRITICAL con arreglo disponible).
# Uso, desde la carpeta del repo API:  .\security\trivy.ps1
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path security/reports | Out-Null
$images = docker compose config --images | Sort-Object -Unique
foreach ($img in $images) {
    $name = ($img -replace '[:/]', '_')
    Write-Host "== $img ==" -ForegroundColor Cyan
    docker run --rm `
        -v //var/run/docker.sock:/var/run/docker.sock `
        -v "${PWD}/security/reports:/reports" `
        aquasec/trivy:latest image --severity HIGH,CRITICAL --ignore-unfixed `
        --format table -o "/reports/trivy_$name.txt" $img
    Get-Content "security/reports/trivy_$name.txt" | Select-Object -First 40
}
