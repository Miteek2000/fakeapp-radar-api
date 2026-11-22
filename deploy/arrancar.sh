#!/usr/bin/env bash
# Levanta todo en el servidor: primero la base, luego la API, la pantalla web y el proxy.
set -euo pipefail
ROOT="$HOME/apkradar"
bash "$ROOT/api/deploy/setup_server.sh"
( cd "$ROOT/db"  && docker compose up -d --build )
( cd "$ROOT/api" && docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build )
( cd "$ROOT/api" && docker compose -f docker-compose.yml -f docker-compose.prod.yml ps )
