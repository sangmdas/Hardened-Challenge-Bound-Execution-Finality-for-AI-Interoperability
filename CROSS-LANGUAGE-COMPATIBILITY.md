# Cross-Language Compatibility — Python ↔ Go

## Purpose

This document records the current cross-language interoperability evidence between the hardened Python reference implementation and the separate Go reference implementation of the execution-finality architecture.

The purpose is to show that core security objects are not dependent on Python-specific behavior, object layout, runtime semantics, or serialization conventions.

The two implementations are separate codebases and runtimes:

- **Python hardened implementation** — primary hardened reference implementation.
- **Go reference implementation** — separately runnable implementation under `go-reference-implementation/`.

The Go implementation does **not** import, call, embed, invoke, or execute the Python implementation.

The implementations are intended to preserve the same architectural security sequence:

```text
Candidate Act
    ->
Protected Validation
    ->
Signed LAVR / Protected Validation Evidence
    ->
Bounded Non-Bearer Execution Capability
    ->
Finality Sink reconstructs actual effect
    ->
Fresh Finality-Sink Challenge
    ->
Live Requester Presentation
    ->
Strict Cross-Object Verification
    ->
Single-Use Consumption
    ->
External Effect
```

This file documents only compatibility properties that have actually been exercised. It does not claim complete formal equivalence between every Python and Go code path.

---

## Implementations

### Python

The hardened Python implementation uses:

- Python 3.11 or later;
- deterministic CBOR encoding;
- COSE_Sign1-style signed objects;
- Ed25519 signatures;
- SHA-256 commitments and digests;
- strict signed-field verification;
- fresh Finality-Sink challenges;
- exact-effect binding;
- requester-key proof of possession;
- protected-channel / execution-context binding;
- single-use capability and challenge state.

### Go

The Go implementation is defined as a separate Go module:

```text
github.com/sangmdas/Hardened-Challenge-Bound-Execution-Finality-for-AI-Interoperability/go-reference-implementation
```

Minimum language declaration:

```text
Go 1.22
```

The Go implementation independently implements:

- deterministic CBOR encoding and decoding;
- strict CBOR parsing;
- COSE_Sign1 construction and verification;
- Ed25519 signing and verification;
- Candidate Act commitments;
- LAVR generation and verification;
- execution-capability generation and verification;
- fresh Finality-Sink challenge generation;
- live requester presentations;
- exact-effect reconstruction and comparison;
- protected-channel binding;
- replay/single-use state;
- revocation and policy-state checks;
- concurrent finality attempts.

No Python runtime is required to execute the Go reference implementation.

---

# Compatibility Method

Cross-language compatibility is tested using deterministic test vectors produced by the hardened Python implementation and verified by the Go implementation.

The current vector file is:

```text
testdata/python_vectors.json
```

It contains deterministic reference values for:

1. **CBOR canonical/deterministic serialization**, and
2. **COSE_Sign1 / Ed25519 signed-object serialization**.

The Go test suite hard-checks those values.

This is stronger than merely checking that both implementations can independently sign and verify their own objects: the test requires the Go implementation to reproduce the same encoded bytes for the tested inputs.

---

# Verified Vector 1 — Deterministic CBOR

Logical value:

```text
{
    1: 2,
    2: "abc",
    3: h'010203',
    4: ["x", 7, true]
}
```

Expected deterministic CBOR bytes:

```text
a40102026361626303430102030483617807f5
```

The Go test constructs the same logical value and requires its encoder to produce exactly:

```text
a40102026361626303430102030483617807f5
```

A byte-level mismatch fails the compatibility test.

### Property Demonstrated

For this vector, the Python and Go implementations agree on:

- integer encoding;
- text-string encoding;
- byte-string encoding;
- array encoding;
- Boolean encoding;
- map-key ordering;
- deterministic map serialization.

This matters because signatures and cryptographic commitments operate over bytes, not abstract programming-language objects. Different serialization of the same logical object would otherwise produce different signatures and digests.

---

# Verified Vector 2 — COSE_Sign1 / Ed25519

The second compatibility vector tests a complete deterministic signed object.

Fixed 32-byte Ed25519 private seed:

```text
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

Key identifier:

```text
kid
```

Payload:

```text
payload
```

Expected COSE_Sign1 token:

```text
8448a2012704436b6964a0477061796c6f61645840a8be91d73412f8f3876d9a52eb045c38ff20964fe626c6950bb246526406386d0b627bbeddf7bf90dfdfbe2c9e646aa2c7b986e7d78a60691247e94cd01a4e0d
```

The Go implementation must generate the exact same byte sequence.

### Property Demonstrated

For this vector, the implementations agree on:

- COSE_Sign1 outer structure;
- protected-header encoding;
- EdDSA/Ed25519 algorithm identifier;
- key identifier placement;
- payload representation;
- Sig_structure construction;
- Ed25519 signing input;
- Ed25519 signature output;
- final deterministic CBOR serialization.

Because Ed25519 signatures are deterministic, the same key, payload, protected headers, and Sig_structure must produce the same signature bytes.

A difference in header construction, CBOR encoding, signing structure, or payload representation would cause this vector to fail.

---

# Go Compatibility Tests

The Go test suite contains explicit compatibility tests including:

```text
TestPythonCBORCompatibilityVector
TestPythonCOSECompatibilityVector
```

Run all Go tests with:

```bash
go test ./...
```

Run with the Go race detector:

```bash
go test -race ./...
```

Run static analysis:

```bash
go vet ./...
```

Run the end-to-end demonstration:

```bash
go run ./cmd/demo
```

A successful demo terminates with:

```text
EFFECT_COMMITTED
```

---

# Security-Relevant Parsing Behavior

Cross-language compatibility is not intended to mean that implementations should accept arbitrary alternate encodings.

Both implementations are intended to behave strictly for security-relevant objects.

The Go test suite includes rejection cases for malformed or non-canonical CBOR and signed-object tampering.

Examples include:

```text
non-minimal integer encodings
trailing data
indefinite-length structures
unsupported CBOR tags
unsupported floating-point values
duplicate map keys
non-deterministic map ordering
tampered COSE payload
tampered COSE signature
unexpected signed fields
missing required signed fields
```

This is important because interoperability should not be achieved by accepting multiple ambiguous representations of a security object.

The preferred rule is:

```text
one logical security object
        ->
one deterministic representation
        ->
one signing input
        ->
one verifiable interpretation
```

---

# Semantic Compatibility

The Go implementation also follows the same principal finality semantics as the hardened Python implementation.

A successful finality operation requires consistency across the relevant security state, including:

```text
Candidate Act
LAVR
Execution Capability
Current Policy / Revocation State
Finality-Sink Challenge
Requester Presentation
Reconstructed Actual Effect
Protected Channel / Execution Context
```

Representative invariants include:

```text
requester(LAVR)
    ==
requester(capability)
    ==
requester(actual_effect)

nonce(LAVR)
    ==
nonce(capability)
    ==
nonce(actual_effect)

sink(capability)
    ==
sink(challenge)
    ==
local_finality_sink

boundary(capability)
    ==
boundary(challenge)
    ==
actual_effect_boundary

effect_commitment(challenge)
    ==
commitment(reconstructed_actual_effect)

requester_key(capability)
    ==
key_used_for_live_presentation
```

The implementations also preserve the intended rule:

```text
valid signature != sufficient authority
```

A correctly signed object is rejected when its signed state is inconsistent with another load-bearing object or with current protected state.

---

# Replay and Challenge Compatibility

Both implementations use the hardened challenge-bound finality model.

A reusable or previously captured requester presentation is not intended to authorize an arbitrary later finality event.

The live requester presentation is bound to security state including:

```text
challenge identifier
challenge nonce
capability digest
Candidate Act identifier
Candidate Act nonce
reconstructed actual-effect commitment
Finality Sink
effectuation boundary
protected-channel / execution-context digest
```

A presentation for Challenge A is therefore not valid for Challenge B.

Similarly, authority bound to Effect A is not intended to authorize Effect B.

---

# What Has Been Demonstrated

The current cross-language evidence supports the following statements:

1. The hardened architecture has separately runnable **Python and Go** implementations.
2. The Go implementation does not depend on the Python runtime.
3. Deterministic CBOR encoding agrees byte-for-byte for the published compatibility vector.
4. COSE_Sign1 / Ed25519 construction agrees byte-for-byte for the published compatibility vector.
5. The Go implementation exercises the same major challenge-bound execution-finality sequence.
6. The Go implementation includes negative tests for replay, substitution, malformed data, signature failure, policy/revocation changes, and concurrent finality attempts.
7. The security model is therefore not expressed only as Python-specific classes or Python-specific serialization behavior.

---

# What Has NOT Yet Been Demonstrated

The current vectors should **not** be described as complete proof that every Python object and every Go object are interchangeable in every possible state.

The current compatibility evidence does not yet establish exhaustive byte-for-byte equivalence for every:

```text
Candidate Act
LAVR
Execution Capability
Finality-Sink Challenge
Requester Presentation
effect record
error representation
future extension field
```

across all valid and invalid combinations.

It also does not prove:

- formal semantic equivalence of the complete Python and Go programs;
- compatibility with an independent third-party implementation;
- interoperability with production Apple, Android, Secure Enclave, TEE, HSM, TPM, or hardware-backed implementations;
- network-protocol interoperability beyond the tested serialization profile;
- backwards compatibility with future profile versions;
- production conformance or standards certification.

The current evidence should therefore be described as:

> **tested cross-language compatibility for deterministic CBOR and COSE_Sign1/Ed25519 primitives, plus separately runnable implementations of the same hardened execution-finality model.**

It should not be described as a complete interoperability certification.

---

# Recommended Next Compatibility Vectors

For stronger independent-implementation evidence, future vectors should cover complete security objects.

Recommended additions are:

```text
1. Candidate Act vector
2. Candidate Act commitment vector
3. LAVR payload and signed-token vector
4. Execution Capability payload and signed-token vector
5. Capability digest vector
6. Finality-Sink Challenge vector
7. Protected-channel-binding digest vector
8. Requester Presentation vector
9. Reconstructed Actual Effect commitment vector
10. Revocation/policy-state mismatch rejection vectors
11. Challenge replay rejection vector
12. Version/downgrade rejection vector
```

For each object, the vector set should ideally include:

```text
logical field representation
canonical encoded bytes
cryptographic digest
signed bytes
expected verification result
expected failure reason for modified variants
```

That would allow Python, Go, Rust, Java, Swift, Kotlin, C/C++, or other independent implementations to validate exactly the same wire/security behavior.

---

# Adding Another Language

A future independent implementation should not copy Python object serialization implicitly.

It should implement the published profile from the specification and then consume the common compatibility vectors.

For example:

```text
                 Specification
                      |
        +-------------+-------------+
        |             |             |
      Python          Go           Rust
        |             |             |
        +-------------+-------------+
                      |
             Common Test Vectors
                      |
              Byte-Level Agreement
```

The compatibility vectors should therefore be treated as an interoperability boundary rather than as implementation-specific fixtures.

---

# Reproducibility

From the `go-reference-implementation/` directory:

```bash
go test ./...
go test -race ./...
go vet ./...
go run ./cmd/demo
```

The Python-generated deterministic vectors used by the Go suite are stored at:

```text
testdata/python_vectors.json
```

The current vectors contain:

```text
CBOR deterministic-encoding vector
COSE_Sign1 / Ed25519 deterministic signed-object vector
```

Any future change to:

- CBOR canonicalization;
- COSE headers;
- signature algorithms;
- key identifiers;
- object versions;
- signed field sets; or
- protected serialization rules

should add or update explicit cross-language vectors rather than relying on undocumented implementation behavior.

---

# Interoperability Principle

The objective is not that different implementations share source code.

The objective is that independently runnable implementations derive the same security meaning from the same canonical security objects.

The governing principle is:

> **Interoperability must preserve the authorization invariant, not merely parse the same syntax.**

For execution finality, that means a conforming implementation must not weaken:

- Candidate Act binding;
- exact-effect binding;
- freshness;
- challenge binding;
- requester-key binding;
- sink/boundary binding;
- policy and revocation state;
- single-use semantics; or
- fail-closed final verification

in order to achieve cross-language compatibility.

---

## Current Status

**Python ↔ Go status:** tested at the deterministic CBOR and COSE_Sign1/Ed25519 primitive level, with separate runnable implementations of the hardened challenge-bound finality flow.

**Current vector source:** `testdata/python_vectors.json`

**Go module:** `go-reference-implementation`

**Status:** reference implementation and interoperability evidence; **not production certification or IETF endorsement**.
