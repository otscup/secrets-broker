#!/usr/bin/env bash
# One-command installer for Secrets Broker (Docker).
# Usage: ./deploy/install.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required: https://docs.docker.com/engine/install/" >&2
  exit 1
fi

mkdir -p deploy data

if [ ! -f deploy/.env ]; then
  echo "Secrets Broker setup"
  echo "--------------------"
  read -r -p "Bitwarden-compatible vault URL (e.g. https://vault.example.com): " BW_SERVER
  read -r -p "Bitwarden personal API key client_id: " BW_CLIENTID
  read -r -s -p "Bitwarden personal API key client_secret: " BW_CLIENTSECRET; echo
  read -r -s -p "Admin password for this broker: " ADMIN_PASSWORD; echo
  read -r -p "Public URL for approval links (leave empty for http://127.0.0.1:8788): " PUBLIC_URL

  cat > deploy/.env <<EOF
BW_SERVER=${BW_SERVER}
BW_CLIENTID=${BW_CLIENTID}
BW_CLIENTSECRET=${BW_CLIENTSECRET}
SECRETS_BROKER_ADMIN_PASSWORD=${ADMIN_PASSWORD}
SECRETS_BROKER_BIND=0.0.0.0
BROKER_PUBLIC_URL=${PUBLIC_URL:-http://127.0.0.1:8788}
EOF
  chmod 600 deploy/.env
  echo "Wrote deploy/.env"
fi

docker compose up -d --build
echo
echo "Secrets Broker is starting."
echo "Open http://127.0.0.1:8788/ and log in with your admin password."
echo "Logs: docker compose logs -f secrets-broker"
