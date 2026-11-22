#!/usr/bin/env bash
# Se ejecuta UNA vez en el servidor. Crea los .env con claves aleatorias generadas ahí mismo
# (nadie las ve ni viajan por ningún lado). Si los .env ya existen, no los toca.
set -euo pipefail
ROOT="$HOME/apkradar"

TOKEN=$(curl -fsS -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
IP=$(curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)
SITE="${IP//./-}.sslip.io"

if [ ! -f "$ROOT/db/.env" ]; then
  DBPASS=$(openssl rand -hex 24)
  cat > "$ROOT/db/.env" <<EOT
POSTGRES_USER=fakeapp
POSTGRES_PASSWORD=$DBPASS
POSTGRES_DB=fakeapp_radar
EOT
  chmod 600 "$ROOT/db/.env"
fi
# shellcheck disable=SC1091
DBPASS=$(grep '^POSTGRES_PASSWORD=' "$ROOT/db/.env" | cut -d= -f2-)

if [ ! -f "$ROOT/api/.env" ]; then
  cat > "$ROOT/api/.env" <<EOT
REDIS_PASSWORD=$(openssl rand -hex 24)
DATABASE_URL=postgresql+psycopg://fakeapp:${DBPASS}@fakeapp-db:5432/fakeapp_radar
ENCRYPTION_KEY=$(openssl rand -base64 32)
JWT_PRIVATE_KEY_B64=$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 | base64 -w0)
RETENTION_DAYS=30
ORPHAN_UPLOAD_HOURS=24
VT_API_KEY=
VT_CACHE_HOURS=24
ALLOW_ANONYMOUS=true
SITE_ADDRESS=$SITE
EOT
  chmod 600 "$ROOT/api/.env"
else
  # La IP cambia cada vez que se reinicia el laboratorio: solo se actualiza la dirección.
  sed -i "s|^SITE_ADDRESS=.*|SITE_ADDRESS=$SITE|" "$ROOT/api/.env"
fi
echo "Listo. Dirección pública: https://$SITE"
