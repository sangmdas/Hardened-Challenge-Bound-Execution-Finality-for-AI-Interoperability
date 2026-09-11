# Security Invariants and Boundaries

## Enforced by this reference implementation

For a successful finality operation, the implementation verifies all of the following:

- valid validator signatures on both LAVR and capability, with the same validator key ID;
- exact LAVR and capability schema versions and exact field sets (no silent omitted/extra signed fields);
- LAVR-to-capability digest binding;
- LAVR, capability and reconstructed actual-effect commitment equality;
- requester equality across LAVR, capability and actual effect;
- nonce equality across LAVR, capability and actual effect;
- Finality Sink and Finality Boundary equality across LAVR, capability, actual effect and local sink identity;
- policy, security and revocation epoch equality across signed objects, actual effect and current policy state;
- current policy still permits the action and destination application;
- signed validation time equals capability issuance time and falls within the Candidate Act validity interval;
- `now >= capability.issued_at` and `now <= capability.expires_at`;
- permitted effect count is exactly one;
- the LAVR predicate list is the exact profile-required list;
- the capability matches protected issued-state stored under its capability ID;
- revocation has not invalidated the requester;
- a fresh sink-issued challenge exists and is not expired;
- challenge context equals the capability digest, reconstructed effect commitment, sink, boundary, protected-channel digest and capability ID;
- requester signature is made by the key whose thumbprint is bound into the capability;
- the signed presentation exactly binds the capability digest, reconstructed effect, act ID, nonce, sink challenge ID/nonce, sink/boundary and protected-channel digest;
- challenge and capability state are single-use within the reference transactional store.

## Not claimed

The reference does **not** establish these deployment properties by itself:

- rollback resistance of SQLite snapshots;
- hardware-backed key custody or Secure Enclave integration;
- authenticity of the platform-provided protected-channel binding;
- non-bypassability of every OS/network/device effectuation path;
- atomicity between SQLite state and a real external side effect such as radio/network transmission;
- resistance to an attacker that can coerce the legitimate requester into signing an attacker-controlled live challenge on the same protected channel;
- trustworthy user intent merely from the Boolean used by this minimal validator interface;
- freshness of policy data if a deployment supplies a stale policy provider;
- production iPhone/Android latency, energy or throughput.

The hardened profile is therefore a runnable verifier model, not a claim that Python + SQLite alone creates a production mobile trust boundary.
