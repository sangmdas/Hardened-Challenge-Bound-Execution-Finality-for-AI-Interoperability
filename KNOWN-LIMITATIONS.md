# Known Limitations

The P0 verifier defects identified in the earlier red-team review are closed in this repository at the reference-protocol level. Several platform-level questions remain intentionally open:

- **Rollback:** SQLite can be snapshotted and restored. Production state must be rollback-protected.
- **Trusted channel binding:** the API requires a protected channel binding but cannot prove its origin. A platform port must derive it from a trusted IPC/audit/attestation context rather than assistant-supplied bytes.
- **Active signing oracle:** a fresh challenge prevents precomputed/static PoP replay. It cannot stop a fully active attacker that can make the legitimate requester sign the attacker's live challenge on the same trusted context; the platform must constrain when and for what UI/IPC context the app key can sign.
- **User intent:** this minimal code still receives `user_intent_verified=True/False`; a production profile should bind user confirmation to protected OS/UI evidence rather than trust an application Boolean.
- **Final external side effect:** the sample commits a database effect record. A production Finality Sink must control the real non-bypassable message/network/payment/storage release path.
- **Hardware keys:** Ed25519 software keys are a portable reference primitive, not evidence of Secure Enclave/TEE/HSM custody.
- **Policy source:** a callable policy provider is supported, but freshness and governance of that provider remain deployment responsibilities.
