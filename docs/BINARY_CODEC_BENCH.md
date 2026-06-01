# Binary Codec Benchmark

GLUV includes a binary wire codec prototype in `src/protocolBinary.ts`.

## Run comparison

```bash
npm run bench:wire:quick
npm run bench:wire:full
```

The benchmark compares `compact-json` vs `binary` for:

- encoded size
- encode/decode micro-latency
- encode/decode ops/s

Results are written to `bench-results/wire-codecs-*.json`.

## Notes

- Binary codec currently targets envelope transport efficiency and deterministic roundtrip.
- Keep compact JSON path for compatibility while binary path is evaluated for broader rollout.
