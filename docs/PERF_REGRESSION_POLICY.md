# 7h3 Protocol AIP Performance Regression Policy

## Purpose

Prevent unreviewed regressions in throughput and tail latency.

## CI gate

- CI must run adaptive open-loop performance gate:
  - `npm run bench:openloop:adaptive:ci`
- Fail build if p99 or drop-rate exceeds configured thresholds.

## Release gate

For release candidates:

1. Run baseline and candidate benchmark suites using `full` profiles.
2. Compare with `npm run bench:diff -- --baseline <...> --candidate <...>`.
3. Block release if either condition is met without explicit waiver:
   - throughput regression beyond accepted threshold
   - p99 regression beyond accepted threshold

## Waiver process

- Waiver requires:
  - documented reason
  - owner
  - rollback plan
  - follow-up due date

## Reporting

- Attach benchmark artifacts and diff report to release PR.
- Record claim context with hardware profile and command set.
