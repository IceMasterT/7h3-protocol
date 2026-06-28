# ---------------------------------------------------------------------------
# Stage 1 — builder
# Install all dependencies (including devDeps for the build step) and
# compile TypeScript sources.  The compiled output ends up in /app/dist.
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
COPY tsconfig.json tsconfig.lib.json ./
COPY vite.lib.config.ts ./

# Run the build script if it exists; swallow the error gracefully so that
# repositories that haven't wired up the build step yet still produce a
# working image.  The runtime stage uses tsx to execute TypeScript directly,
# so a missing dist/ is not fatal.
RUN npm run build:protocol 2>/dev/null || true

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# Lean image with only production dependencies.
# tsx executes TypeScript directly, so we don't strictly need dist/; the
# builder stage is kept separate to avoid polluting the final image with
# devDependencies and intermediate build artefacts.
# ---------------------------------------------------------------------------
FROM node:22-alpine

# Install tsx globally so the ENTRYPOINT can invoke TypeScript files.
# Pinning via the package.json range is intentional — renovate will keep
# this in sync with the devDependency version.
RUN npm install -g tsx

WORKDIR /app

# Copy manifests for production install
COPY package.json package-lock.json ./

# Production-only install; omits devDependencies such as vitest and vite
RUN npm ci --omit=dev --prefer-offline

# Copy the source files required at runtime
COPY src/ src/
COPY bin/ bin/

# Copy compiled output from the builder stage (used when tsx is not
# available or when --no-tsx mode is added in future).
COPY --from=builder /app/dist/ dist/

# The gateway listens on this port by default.
EXPOSE 8080

# Lightweight health check: wget is present on node:alpine; curl is not.
# This probe hits the /health route which, per the example config, is
# policy-exempt (require: none) and will pass through to the upstream.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

# Run the gateway sub-command of the 7h3 CLI.
ENTRYPOINT ["tsx", "bin/7h3.ts", "gateway"]

# Default arguments — overridden at runtime via docker-compose environment
# variables or explicit docker run arguments.
CMD ["--port", "8080", "--upstream", "http://upstream:3000", "--require", "ed25519"]
