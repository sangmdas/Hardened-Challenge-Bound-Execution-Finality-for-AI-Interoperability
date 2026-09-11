# Hardened Execution-Finality Reference Implementation for AI Interoperability

This repository is a **separate hardened follow-on reference implementation** to the earlier runnable AI-interoperability prototype. It specifically closes four P0 issues exposed by adversarial review:

1. **live Finality-Sink challenge for proof of possession** rather than a reusable precomputed presentation;
2. **strict LAVR/capability schemas and field-by-field cross-checking** at the Finality Sink;
3. **explicit not-before, expiry, validation-time, challenge-freshness, and current-policy enforcement**; and
4. **security documentation that states exactly what the code verifies and what it does not prove**.

The reference flow is:

`Candidate Act -> protected validation -> signed LAVR -> signed fractional capability -> sink-issued fresh challenge -> requester-key presentation bound to challenge + actual effect + protected channel context -> strict Finality Sink verification -> atomic challenge/capability consumption -> effect commit`

## Why the challenge was added

A capability can be non-bearer yet still be weak if the associated proof-of-possession presentation can be prepared once and captured. This profile therefore requires the Finality Sink to issue a short-lived random challenge **after authority exists and before final effectuation**. The requester signs that challenge together with the capability digest and actual-effect commitment.

The reference additionally requires a `protected_channel_binding` supplied by the trusted platform integration. This is intended to represent an OS-mediated IPC/audit-token/attested-channel binding. The Python library cannot itself prove that those bytes came from a real iOS/Android protected channel; that is a deployment obligation.

## Strict verifier behavior

The Finality Sink rejects missing or additional signed fields. It independently cross-checks requester, nonce, sink, boundary, policy/security/revocation epochs, LAVR digest, Candidate Act commitment, validation time, expiry, permitted effect count, predicate set, requester-key thumbprint, challenge context, protected-channel binding and the reconstructed actual consequence.

## Freshness behavior

The hardened profile is strict by default:

- a Candidate Act cannot be validated before `issued_at`;
- a capability cannot be used before its signed `issued_at`;
- a capability cannot be used after expiry;
- a challenge has a 1-30 second validity window (5 seconds by default);
- the challenge is bound to one capability, one reconstructed effect, one Finality Sink, one boundary, one protected channel context and one capability ID;
- the challenge and capability are consumed atomically with the reference effect record.

## Run

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

## What this does **not** prove

This repository does **not** claim to be an Apple, Android, DMA-compliance, Secure Enclave or production OS implementation. In particular, plain SQLite is not rollback-resistant trusted storage; Python Ed25519 keys are not evidence of Secure Enclave key custody; the library does not make alternate OS egress paths non-bypassable; and active relay resistance ultimately depends on the platform supplying an unforgeable protected-channel binding and preventing the attacker from using the legitimate requester as a signing oracle.

## Verification status

The repository currently contains **100 executable tests**:

- 34 hardened finality/state/concurrency tests;
- 24 strict signed-field and cross-object consistency tests;
- 17 challenge/presentation schema and substitution tests;
- 24 deterministic CBOR/COSE parsing and signature tests; and
- 1 explicit known-limitation test demonstrating that an ordinary SQLite snapshot rollback can restore reference-state consumability.

All 100 tests completed successfully in the recorded local run. The known-limitation test is deliberately evidence of a remaining platform limitation, not a security property.

The matching Internet-Draft source is included at `spec/draft-das-execution-finality-ai-interoperability-03.xml`.

See `SECURITY.md`, `KNOWN-LIMITATIONS.md`, `TEST-REPORT.md`, and `IETF-03-CHANGE-NOTES.md` before making security or performance claims.
