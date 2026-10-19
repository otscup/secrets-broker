FROM node:24-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g @bitwarden/cli@2026.10.0

WORKDIR /app
COPY server.mjs /app/server.mjs
COPY deploy/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV SECRETS_BROKER_HOME=/data \
    SECRETS_BROKER_PORT=8788 \
    SECRETS_BROKER_BIND=0.0.0.0 \
    SECRETS_BROKER_BW=/usr/local/lib/node_modules/@bitwarden/cli/build/bw.js \
    HOME=/data/home

VOLUME ["/data"]
EXPOSE 8788
ENTRYPOINT ["/app/entrypoint.sh"]
