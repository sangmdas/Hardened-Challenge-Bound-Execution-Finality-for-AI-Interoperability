# Changelog

## 0.2.0 — P0 hardening profile

- Added short-lived Finality-Sink challenge.
- Bound requester proof to challenge ID, challenge nonce, capability digest, actual-effect commitment, sink, boundary and protected-channel digest.
- Added exact signed-object schemas and rejection of missing/extra fields.
- Added field-by-field LAVR/capability/effect/current-policy cross-checks.
- Added strict capability not-before and expiry checks.
- Added strict LAVR validation-time/capability issuance-time equality.
- Added challenge freshness and single-use state.
- Added current action/destination policy re-check at finality.
- Added exact permitted-effect-count enforcement.
- Added issued-state cross-check before challenge issuance/finality.
- Rewrote security claims to distinguish protocol checks from platform assumptions.

- Added deterministic CBOR/COSE strictness tests.
- Added duplicate Candidate Act identifier rejection at issuance.
- Added the matching Internet-Draft `-03` source and P0 change notes.
- Current executable suite: 100 tests; one is an explicit SQLite rollback limitation demonstration.
