# Sube los tres proyectos al servidor AWS y los levanta. Uso (PowerShell):
#   .\deploy\subir.ps1 -Ip 54.221.43.212
param([Parameter(Mandatory=$true)][string]$Ip)

$base  = "C:\Users\Mitee\OneDrive\Documentos\Proyecto FakeApp"
$llave = "$base\aws-llaves\apkradar-aws"
$tmp   = Join-Path $env:TEMP "apkradar-deploy"
New-Item -ItemType Directory -Force $tmp | Out-Null

# Se excluyen .git, .env (secretos), entornos virtuales, node_modules, APK de prueba y reportes.
tar -czf "$tmp\db.tgz"  --exclude=.git --exclude=.env --exclude=node_modules -C "$base\DB\fakeapp-radar-db" .
tar -czf "$tmp\api.tgz" --exclude=.git --exclude=.venv --exclude=.env --exclude=__pycache__ --exclude=.pytest_cache --exclude=uploads --exclude=*.apk --exclude=reports -C "$base\Backend\fakeapp-radar-api" .
tar -czf "$tmp\web.tgz" --exclude=.git --exclude=node_modules --exclude=.next --exclude=.env --exclude=reports -C "$base\Frontend\fakeapp-radar-web\fakeapp" .

$ssh = @("-i", $llave, "-o", "StrictHostKeyChecking=accept-new")
scp @ssh "$tmp\db.tgz" "$tmp\api.tgz" "$tmp\web.tgz" "ubuntu@${Ip}:/tmp/"
ssh @ssh "ubuntu@$Ip" "mkdir -p ~/apkradar/db ~/apkradar/api ~/apkradar/web && tar -xzf /tmp/db.tgz -C ~/apkradar/db && tar -xzf /tmp/api.tgz -C ~/apkradar/api && tar -xzf /tmp/web.tgz -C ~/apkradar/web && rm /tmp/*.tgz && bash ~/apkradar/api/deploy/arrancar.sh"
