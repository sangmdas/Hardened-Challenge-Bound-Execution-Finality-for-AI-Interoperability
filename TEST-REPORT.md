# Hardened Reference Implementation — Test Report

Date: 2026-09-11

## Result

`python -m unittest discover -s tests -v`

**100 tests executed; test runner result: OK.**

This does **not** mean 100 security properties have been proven. One test intentionally demonstrates the known SQLite rollback limitation.

## Test groups

| Group | Count | Purpose |
|---|---:|---|
| Hardened finality/state/concurrency | 34 | Live challenge, replay, field substitution, policy/revocation changes, concurrency, issuance uniqueness |
| Strict LAVR/capability verification | 24 | Exact schemas, signed-field cross-checks, time/epoch/sink/boundary consistency |
| Challenge/presentation schema | 17 | Challenge and PoP field substitution, missing/extra fields, channel/sink/boundary binding |
| Deterministic CBOR/COSE | 24 | Canonical encoding, malformed input, duplicate/noncanonical keys, signature/header tampering |
| Known limitation | 1 | Demonstrates ordinary SQLite snapshot rollback can restore consumability |

## Local execution environment

- Python 3.13.5
- Linux 6.18.35 x86-64
- `cryptography` 46.0.4
- package installed editable with `--no-build-isolation` using locally installed build dependencies, then the full suite rerun without `PYTHONPATH`

The GitHub Actions workflow separately defines Ubuntu and macOS runs for Python 3.11, 3.12 and 3.13. Those CI combinations should only be claimed as tested after GitHub Actions actually executes them.

## P0 closure tests

The suite directly checks that a presentation created for Challenge A fails against Challenge B; missing/wrong protected-channel binding fails; expired challenges fail; requester-key substitution fails; capability use is single-use; concurrent attempts yield one commit; capability `issued_at` is enforced; LAVR/capability time mismatch fails; extra and missing LAVR/capability fields fail; and signed requester, nonce, sink, boundary, epochs, expiry, predicate set and use count are independently cross-checked.

## Remaining platform questions

See `KNOWN-LIMITATIONS.md`. The most important unresolved production properties are trusted derivation of protected channel binding, rollback-resistant state, protected user-intent evidence, hardware key custody, complete mediation/non-bypassability, and atomicity with the real external side effect.
