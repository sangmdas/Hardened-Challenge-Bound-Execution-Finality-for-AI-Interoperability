# Internet-Draft -03 P0 Hardening Changes

Source: `spec/draft-das-execution-finality-ai-interoperability-03.xml`

The `-03` source is derived from the current `-02` XML and changes the execution-finality security mechanics rather than merely adding explanatory prose.

## P0-1 — Live Finality-Sink challenge

The sink now issues a fresh, unpredictable, short-lived challenge after authority validation and before finality. The requester presentation binds the challenge ID/nonce, capability digest, actual-effect commitment, Candidate Act ID/nonce, sink, boundary, and protected-channel digest. A presentation captured for one challenge cannot satisfy another fresh challenge.

The text explicitly states that active-relay resistance still requires the protected channel binding to be derived from platform-controlled context that untrusted requester software cannot forge.

## P0-2 — Strict signed-object schema and cross-checking

The sink is required to reject missing or additional fields and cross-check duplicated load-bearing fields across Candidate Act, LAVR, capability, reconstructed effect and current protected state. This includes requester, commitment, LAVR digest, key binding, nonce, sink, boundary, policy/security/revocation epochs, times, permitted effect count and predicates.

## P0-3 — Not-before and freshness

The capability is invalid before signed issuance and after expiry. LAVR validation time and capability issuance time must agree and fall within the Candidate Act validity interval. Challenges are short-lived and single-use. Current governance and revocation state is rechecked immediately before protected consumption.

## P0-4 — Security-claim correction

The new text no longer relies on the broad statement that copying a capability is simply impossible/useful. It specifies exactly what makes possession insufficient and explicitly identifies platform assumptions not established by the Python reference implementation.

## Workflow and pseudocode

The workflow now inserts a `LIVE SINK CHALLENGE` stage before Finality Sink effectuation. The pseudocode defines separate challenge issuance, requester-presentation creation, and finalization phases with revalidation and atomic challenge/capability consumption.

## Non-claim

This revision does not claim that Python, SQLite, or a caller-provided byte string establishes a production iOS trust boundary. Platform integration is still required for protected key custody, trustworthy channel/context derivation, rollback resistance, complete mediation and real-side-effect atomicity.
