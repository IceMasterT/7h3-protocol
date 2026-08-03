# ---------------------------------------------------------------------------
# Stage 1 — builder
# Install all dependencies (including devDeps for the build step) and
# compile TypeScript sources.  The compiled output ends up in /app/dist and
# /app/bin/7h3.js.
# ---------------------------------------------------------------------------
FROM node:22-alpine AS builder

WORKDIR /app

# Copy manifests first so Docker can cache the install layer separately
# from source changes.
COPY package.json package-lock.json ./

# Install all deps (dev + prod) needed to build
RUN npm ci --prefer-offline

# Copy the full source tree
COPY src/ src/
COPY bin/ bin/
COPY scripts/build-cli.ts ./scripts/build-cli.ts
COPY tsconfig.json tsconfig.lib.json tsconfig.bin.json ./
COPY vite.lib.config.ts ./

# Build must succeed — the runtime stage below ships the compiled CLI
# (bin/7h3.js) and library bundle (dist/protocol/index.js), not TypeScript
# source, so a broken build here must fail the image build, not silently
# produce a runtime that fails on its first request instead.
RUN npm run build:protocol && npm run build:cli

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# Lean image with only production dependencies and compiled output — no
# devDependencies, no TypeScript source, no tsx runtime required.
# ---------------------------------------------------------------------------
FROM node:22-alpine

WORKDIR /app

# Copy manifests for production install
COPY package.json package-lock.json ./

# Production-only install; omits devDependencies such as vitest and vite
RUN npm ci --omit=dev --prefer-offline

# Copy compiled output from the builder stage.
COPY --from=builder /app/dist/ dist/
COPY --from=builder /app/bin/7h3.js bin/7h3.js

# The gateway listens on this port by default.
EXPOSE 8080

# Lightweight health check: wget is present on node:alpine; curl is not.
# This probe hits the /health route which, per the example config, is
# policy-exempt (require: none) and will pass through to the upstream.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

# Run the gateway sub-command of the compiled 7h3 CLI.
ENTRYPOINT ["node", "bin/7h3.js", "gateway"]

# Default arguments — overridden at runtime via docker-compose environment
# variables or explicit docker run arguments.
CMD ["--port", "8080", "--upstream", "http://upstream:3000", "--require", "ed25519"]
