# Security Policy

## Reporting a Vulnerability

Please do not open a GitHub Issue for security findings. Use coordinated disclosure instead.

**Send private reports to:** tech@mysms.promo  
**Subject line:** `[7h3 Security] <brief description>`

### What to include

A useful report contains:

- A clear description of the vulnerability and which component it affects
- Steps to reproduce, ideally as a minimal test case or fixture
- Your assessment of the impact (confidentiality, integrity, availability, scope)
- The affected versions (check `package.json` version and the wire version `7h3/0.1`)
- Any suggested fix or mitigation you have in mind (optional but appreciated)

Reports that include a conformance vector demonstrating the issue are especially
helpful and make the triage process faster.

## Response Timeline

| Event | Target |
|---|---|
| Acknowledgement | 48 hours |
| Triage and severity assignment | 5 business days |
| Patch for critical/high severity | 14 days from confirmation |
| Patch for medium/low severity | 60 days from confirmation |
| Public disclosure | After patch is released and verified |

We ask that reporters hold off on public disclosure until a patch is available.
If the 14-day critical window is going to slip, we will contact you to agree on
an extended timeline or coordinated partial disclosure.

## Scope

The following are in scope:

- Envelope signing and verification (`src/`, `sdk/python/`, `sdk/rust/`)
- Canonicalization logic and determinism guarantees
- Replay-safety (nonce and timestamp validation)
- Wire format parsing in all three runtimes (TypeScript, Python, Rust)
- Intent vocabulary validation

Out of scope: third-party dependencies (report those upstream), benchmark
scripts, and documentation typos.

## Audit Status

No independent third-party security audit has been performed on this codebase
as of the current release. The protocol design has been reviewed by the
maintainer against known attack classes for signed messaging systems, but that
is not a substitute for a formal audit. Reproductions of conformance vectors
that reveal edge-case signing or deserialization behavior are welcome and
treated as high-value contributions.

## Hall of Thanks

Researchers who report valid, confirmed vulnerabilities will be acknowledged
here (with their permission).

_No entries yet._

---

Maintainer: [@IceMasterT](https://github.com/IceMasterT)  
Package: `@7h3/protocol`  
License: MIT
