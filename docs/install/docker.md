# Install: Docker

Runs the verifying gateway as a container. There is **no published image** —
build it from this repository.

## Build

```bash
git clone https://github.com/IceMasterT/7h3-protocol.git
cd 7h3-protocol
docker build -t 7h3-gateway .
```

## Run

```bash
docker run -p 8080:8080 \
  -e GATEWAY_PRIVATE_KEY="$(cat key.txt)" \
  7h3-gateway --upstream http://your-api:3000 --require ed25519
```

The image exposes **8080**, entrypoints to `node bin/7h3.js gateway`, and has a
health check on `/health`. Everything after the image name is passed to the
gateway, so any [CLI flag](./cli.md) works.

Defaults if you pass nothing: `--port 8080 --upstream http://upstream:3000
--require ed25519`.

## docker compose

The repo ships a `docker-compose.yaml` with two services — `gateway` and a
placeholder `api` upstream:

```bash
docker compose up
```

Point `api` at your own service, or replace it entirely.

## Secrets

Pass the private key by environment variable (`GATEWAY_PRIVATE_KEY`) or mount a
file and use `--private-key-file`. Never bake a key into the image, and avoid
`--private-key` on the command line — it lands in process listings.
