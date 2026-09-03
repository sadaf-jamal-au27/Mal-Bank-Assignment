# Minimal, non-root, digest-pinned base — the application code itself is
# assumed to exist and be "broadly competent" per the assessment brief.
# This Dockerfile exists only so build-scan-sign in CI has something real
# to build, scan, and sign.
FROM node:20-alpine@sha256:2d07db07a2df6830718ae2a47db6fedce6745f5bcd174c398f0ce203bb827519 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

FROM node:20-alpine@sha256:2d07db07a2df6830718ae2a47db6fedce6745f5bcd174c398f0ce203bb827519
RUN addgroup -g 10001 accounts-api && adduser -D -u 10001 -G accounts-api accounts-api
WORKDIR /app
COPY --from=build --chown=accounts-api:accounts-api /app .
USER 10001
EXPOSE 8080
ENTRYPOINT ["node", "server.js"]
