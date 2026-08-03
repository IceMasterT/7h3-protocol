# 7h3 Protocol Release Gate

Run this gate before publishing protocol performance claims or changing transport defaults.

```bash
npm run release:gate
```

The gate runs runtime policy validation, tests, the protocol build, lint, wire benchmarks, and an adaptive open-loop check. For release candidates, also run:

```bash
npm run bench:wire:full
npm run bench:replay:full
npm run bench:openloop:full
npm run conformance:binary
npm run conformance:python
npm run conformance:rust
```

## Rollout Rules

- Compact JSON remains the default wire format for `7h3/0.1` compatibility.
- Binary wire and binary WebSocket modes are opt-in until negotiated through `CAPS`.
- Signature verification, replay defense, TTL validation, and canonicalization must stay enabled in all benchmark claims.
- README performance numbers must come from fresh benchmark artifacts committed or attached to the release.
