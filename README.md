# Hardened Execution-Finality Reference Implementation for AI Interoperability

## Implementation Reference Version 2

This repository contains **Implementation Reference Version 2**, a separate hardened follow-on to the earlier runnable execution-finality implementation for secure and privacy-preserving AI interoperability.

### Predecessor implementation

The predecessor repository is:

**Secure and Privacy-Preserving AI Interoperability for Third-Party Tools**

https://github.com/sangmdas/Secure-and-Privacy-Preserving-AI-Interoperability-for-Third-Party-Tools

The predecessor established the initial runnable implementation of the architecture:

```text
Candidate Act
        ->
Non-Effective State
        ->
Protected Validation
        ->
LAVR / Validation Evidence
        ->
Narrow Execution Capability
        ->
Finality Sink Verification
        ->
External Effect
```

Implementation Reference Version 2 retains that architectural model but significantly strengthens the security behavior immediately before effectuation.

It was produced after adversarial review of the predecessor implementation identified several areas where the executable realization could be made materially stronger.

---

# What Is Different from the Predecessor?

The predecessor demonstrated the core execution-finality principle:

> **An AI system may request or prepare an operation, but the request itself does not constitute authority for that operation to become externally effective.**

Implementation Reference Version 2 keeps that invariant but introduces additional mechanisms to address weaknesses discovered through implementation and adversarial testing.

The four principal P0 changes are:

1. **live Finality-Sink challenge-based proof of possession** instead of relying on a potentially reusable precomputed presentation;

2. **strict LAVR and execution-capability schemas with field-by-field and cross-object verification** at the Finality Sink;

3. **explicit not-before, expiry, validation-time, challenge-freshness, current-policy, epoch, and revocation enforcement**; and

4. **precise security documentation separating what the reference code actually verifies from properties that still depend on protected operating-system or hardware integration.**

The hardened reference flow is:

```text
Candidate Act
      |
      v
Non-Effective State
      |
      v
Protected Validation
      |
      +----> Signed LAVR
      |
      +----> Narrow / Fractional Execution Capability
      |
      v
Finality Sink reconstructs actual consequence
      |
      v
Strict capability + LAVR verification
      |
      v
Current policy / epoch / revocation verification
      |
      v
Fresh Finality-Sink challenge
      |
      v
Requester produces live challenge-bound presentation
      |
      v
Presentation bound to:
    challenge
    capability
    Candidate Act
    actual effect
    sink
    boundary
    protected channel / execution context
      |
      v
Cross-object consistency verification
      |
      v
Atomic challenge + capability consumption
      |
      v
External Effect
```

The change is therefore not merely additional validation code.

It strengthens the distinction between:

```text
possessing authorization material
```

and:

```text
having current authority for this exact
consequence at this exact finality event
```

---

# Related IETF Internet-Draft

The architecture and its broader technical reasoning are described in the associated IETF Internet-Draft:

**Breaking the Apple-Siri EU DMA Deadlock Without Sacrificing Privacy or Security**

**draft-das-execution-finality-ai-interoperability**

https://datatracker.ietf.org/doc/draft-das-execution-finality-ai-interoperability/

The Internet-Draft discusses the broader architecture independently of this particular Python reference implementation.

This repository should therefore be read as an **executable implementation reference**, while the Internet-Draft provides the broader architectural, interoperability, security, deployment, objection-response, and standards-oriented discussion.

The matching XML source used with this hardened implementation is also included in this repository:

```text
spec/draft-das-execution-finality-ai-interoperability-03.xml
```

---

# Apple/Siri — EU Interoperability Context

One motivating use case for the architecture is the technical tension around third-party AI-assistant interoperability on mobile operating systems.

The problem is not simply whether another AI assistant should be allowed to call an API.

The harder question is:

> **How can a platform allow meaningful participation by a third-party AI assistant without converting that interoperability permission into broad or reusable execution authority over messages, files, payments, device functions, applications, sensors, or other consequential operations?**

This issue was discussed separately in the EU Apply AI Alliance / Futurium technical note:

**Breaking the Siri–EU Deadlock: Hardware-Rooted Execution Finality as the Missing Interoperability Mechanism**

https://futurium.ec.europa.eu/en/apply-ai-alliance/community-content/breaking-siri-eu-deadlock-hardware-rooted-execution-finality-missing-interoperability-mechanism

The technical objective is not to weaken platform security in order to obtain interoperability.

The proposed direction is instead:

```text
OPEN PARTICIPATION
        +
BOUNDED AUTHORITY
        +
INDEPENDENT FINAL VERIFICATION
        +
FAIL-CLOSED EFFECTUATION
```

A third-party assistant may therefore be permitted to request or prepare an operation without automatically acquiring unrestricted authority to cause the corresponding external consequence.

The Finality Sink remains responsible for determining whether the exact operation may become effective.

---

# Why the Fresh Challenge Was Added

A capability can be non-bearer and still have a weakness if its associated proof-of-possession presentation can be generated once, captured, and relayed.

The predecessor implementation bound a requester-key presentation to the Candidate Act and capability.

That prevented possession of the capability alone from being sufficient.

However, adversarial review identified a stronger requirement:

```text
proof that the requester possessed the key earlier
```

should not automatically be treated as equivalent to:

```text
proof that the requester is participating
in this specific finality attempt now
```

Implementation Reference Version 2 therefore requires the Finality Sink to issue a **fresh, short-lived, unpredictable challenge after authority exists and before effectuation**.

The requester must sign a presentation bound to:

```text
challenge identifier
challenge nonce
capability digest
actual-effect commitment
Candidate Act identifier
Candidate Act nonce
Finality Sink identity
effectuation boundary
protected channel / execution-context binding
```

A presentation produced for another challenge cannot authorize a new finality attempt.

A captured capability together with an earlier presentation is therefore insufficient by itself.

---

# Single-Use Challenge State

The challenge is not merely an informational nonce.

It is security state associated with one finality attempt.

A challenge contains or is bound to:

```text
challenge identifier
unpredictable challenge nonce
capability digest
actual-effect commitment
Finality Sink
effectuation boundary
protected channel context
issuance time
expiry
consumption state
```

The Finality Sink rejects a challenge that is:

```text
unknown
expired
already consumed
bound to another capability
bound to another effect
bound to another Finality Sink
bound to another boundary
bound to another protected context
```

Successful finality consumes the challenge together with the applicable execution authority.

---

# Exact-Effect Binding

Implementation Reference Version 2 binds the live requester proof to the consequence reconstructed at the Finality Sink.

For example:

```text
action      = SEND
resource    = X
destination = A
```

cannot silently become:

```text
action      = SEND
resource    = X
destination = B
```

while retaining the same valid finality presentation.

The intended relationship is:

```text
effect approved in the live presentation

                ==

effect reconstructed at the Finality Sink

                ==

effect allowed to become externally effective
```

This is a core distinction between execution-finality authority and a conventional reusable permission token.

---

# Strict LAVR and Capability Verification

A valid signature only proves that the holder of a signing key signed a particular byte sequence.

It does not automatically prove that:

```text
all required fields exist
the object has the expected schema
the values are semantically consistent
the object corresponds to current state
the object belongs to the correct protocol profile
the object is current rather than stale
```

Implementation Reference Version 2 therefore performs strict verification of both LAVR / protected validation evidence and execution capabilities.

Security-relevant fields are checked individually rather than assuming that successful signature verification is sufficient.

The Finality Sink verifies and cross-checks values including, as applicable:

```text
Candidate Act commitment
Candidate Act identifier
Candidate Act nonce
requester identity
requester-key thumbprint
resource commitment
destination
destination application
LAVR digest
Finality Sink
effectuation boundary
policy version
security epoch
revocation epoch
required predicates
permitted effect count
validation time
capability issuance time
capability expiry
challenge identifier
challenge nonce
actual-effect commitment
protected-channel binding
```

Missing, additional, malformed, contradictory, non-canonical, or semantically inconsistent security state causes fail-closed rejection where the applicable strict schema requires it.

---

# Cross-Object Verification

Version 2 does not evaluate each signed object in isolation.

The Finality Sink cross-checks the complete authorization chain:

```text
Candidate Act
       +
LAVR / Protected Validation Evidence
       +
Execution Capability
       +
Current Protected State
       +
Finality-Sink Challenge
       +
Requester Presentation
       +
Reconstructed Actual Effect
```

A correctly signed capability can therefore still be rejected when its contents contradict the Candidate Act, LAVR, current epoch state, challenge, requester presentation, or actual consequence.

This is intended to provide defense in depth against:

```text
trusted-component implementation defects
incorrect capability construction
partial state substitution
stale-object combinations
parser disagreement
misconfiguration
signing-key misuse
```

---

# Freshness and Temporal Validation

The hardened profile validates more than expiry.

Representative conditions include:

```text
validation_time <= capability_issued_at

capability_issued_at <= current_protected_time

current_protected_time <= capability_expires_at

challenge_issued_at <= current_protected_time

current_protected_time <= challenge_expires_at
```

The reference challenge validity window is configurable within a bounded range, with a short default lifetime.

A capability whose signed issuance time lies in the future is not considered currently valid simply because its expiration time also lies in the future.

Production systems may additionally apply appropriate trusted-clock and bounded-skew policies.

---

# Protected Channel / Execution-Context Binding

Cryptographic private-key possession is not necessarily equivalent to execution by the intended application or protected process.

Version 2 therefore introduces:

```text
protected_channel_binding
```

The reference value represents a protected platform-derived relationship between the live requester presentation and the context through which the finality operation is being performed.

A production realization may derive equivalent state from mechanisms such as:

```text
protected IPC identity
OS audit credentials
code-signing identity
application identity
hardware-backed application identity
authenticated channel state
device-bound key state
attested workload identity
protected process credentials
secure execution context
```

The Python reference implementation cannot prove that arbitrary bytes supplied as `protected_channel_binding` originated from a genuine iOS, Android, Secure Enclave, TEE, or protected OS channel.

That is deliberately documented as a **platform integration requirement**, not hidden as an implementation assumption.

---

# Replay and Concurrency Model

Implementation Reference Version 2 distinguishes several different replay conditions:

```text
capability replay after consumption
challenge replay after consumption
presentation replay against another challenge
presentation replay against another effect
concurrent first-use attempts
concurrent attempts involving different sinks
persistent-state rollback
```

The first classes are addressed using combinations of:

```text
single-use capability state
single-use challenge state
fresh challenge generation
live requester proof
actual-effect binding
atomic consumption
transactional conflict handling
```

Persistent-state rollback is treated separately because ordinary digital signatures do not make a database rollback resistant.

---

# Fail-Closed Finality

The Finality Sink does not treat partial success as sufficient.

Conceptually:

```text
VERIFY capability

VERIFY LAVR

VERIFY current policy state

VERIFY security epoch

VERIFY revocation epoch

VERIFY temporal validity

VERIFY reconstructed effect

VERIFY fresh challenge

VERIFY requester presentation

VERIFY protected context binding

VERIFY cross-object consistency

VERIFY capability unused

VERIFY challenge unused

ONLY THEN:

ATOMically consume authority
        ->
permit External Effect
```

The design explicitly rejects:

```text
perform consequential action first
        ->
check / audit / record authorization afterward
```

The enforcement point is intended to remain **pre-effectuation**.

---

# Version 1 and Version 2 Are Not Silently Interchangeable

Implementation Reference Version 2 introduces additional security objects and stronger verification semantics.

Therefore:

> **Version 1 and Version 2 security objects must not silently fall back to a common weaker interpretation.**

Expected behavior includes:

```text
unknown security version
        -> REJECT

missing required Version 2 field
        -> REJECT

unsupported challenge profile
        -> REJECT

unexpected security-relevant field
        -> REJECT where strict schema applies

silent Version 2 -> Version 1 downgrade
        -> PROHIBITED
```

This requirement is important for independent implementations.

Security behavior must not depend on whether an old or new parser happens to receive the same object.

---

# Expanded Verification Suite

Implementation Reference Version 2 currently contains **100 executable tests**.

The suite consists of:

* **34 hardened finality, state, and concurrency tests**
* **24 strict signed-field and cross-object consistency tests**
* **17 challenge/presentation schema and substitution tests**
* **24 deterministic CBOR/COSE parsing and signature tests**
* **1 explicit known-limitation test**

The test surface includes:

```text
Candidate Act integrity
resource substitution
destination substitution
requester substitution
Finality-Sink substitution
boundary substitution
requester-key substitution

capability replay
challenge replay
presentation replay
concurrent first use

post-issuance revocation
policy-version changes
security-epoch changes
revocation-epoch changes

future issuance
expiry
challenge freshness

LAVR / capability inconsistency
missing signed fields
unexpected signed fields

malformed CBOR
non-canonical CBOR
COSE/signature failure

challenge mismatch
actual-effect mismatch
execution-context mismatch

atomic state consumption
rollback limitation characterization
```

All 100 tests completed successfully in the recorded reference run.

The rollback test requires an important qualification:

> **The rollback test demonstrates a known limitation; it is not evidence that rollback resistance has been solved.**

Restoring an earlier ordinary SQLite snapshot can restore reference-state consumability.

Production rollback resistance therefore requires protected platform state or another authoritative mechanism.

---

# Frequently Asked Questions and Technical Objections

Many of the principal technical questions that naturally arise from this repository are already discussed in the associated **IETF Internet-Draft**, including questions concerning:

```text
where the Finality Sink belongs

how alternate egress paths are handled

whether the architecture requires new hardware

how legacy systems can participate

what makes the capability non-bearer

what happens if a policy changes

how revocation operates

how first-party / third-party parity is evaluated

how policy provenance is governed

how failure is handled

what must remain atomic

how the architecture relates to existing authorization mechanisms

what happens when a protected component is compromised

how the architecture can be incrementally deployed

what remains platform-specific
```

Readers evaluating the architecture are therefore encouraged to review the Internet-Draft together with this repository.

The GitHub implementation demonstrates executable behavior.

The Internet-Draft contains the broader architectural reasoning, anticipated technical objections, deployment discussion, security considerations, interoperability implications, and explanatory FAQ-style material.

Not every future implementation question can be answered by a portable reference implementation, and some matters remain intentionally platform dependent.

Those limitations are identified rather than being represented as solved.

---

# What This Reference Implementation Does Not Prove

This repository does **not** claim to be:

```text
an Apple implementation
an iOS implementation
an Android implementation
a DMA-conformance implementation
a Secure Enclave implementation
a TEE implementation
an OS security certification
a production-device security certification
```

In particular:

* ordinary SQLite is not rollback-resistant trusted storage;
* Python Ed25519 keys are not evidence of hardware-backed or Secure Enclave key custody;
* the reference library does not make alternate OS egress paths physically non-bypassable;
* the library cannot independently prove that a supplied channel binding originated from a protected OS mechanism;
* active relay resistance ultimately depends on correct protected-platform integration;
* production user-intent evidence may require stronger platform mechanisms;
* trusted time remains a deployment consideration; and
* an SQLite transaction cannot by itself make an arbitrary irreversible remote network effect atomic.

These limitations define the boundary between:

```text
REFERENCE PROTOCOL BEHAVIOR
```

and:

```text
PRODUCTION PLATFORM ENFORCEMENT
```

They should not be conflated.

---

# Running the Reference Implementation

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

See the following files before making security or performance claims:

```text
SECURITY.md
KNOWN-LIMITATIONS.md
TEST-REPORT.md
IETF-03-CHANGE-NOTES.md
```

The corresponding Internet-Draft XML source is included under:

```text
spec/draft-das-execution-finality-ai-interoperability-03.xml
```

---

# Version 1 → Version 2 at a Glance

```text
PREDECESSOR                         HARDENED VERSION 2

Static requester presentation  ->  Fresh sink challenge

Proof of key possession        ->  Live finality-time proof

Capability-bound proof         ->  Exact-effect-bound proof

Partial field verification     ->  Strict schemas

Individually signed objects    ->  Cross-object verification

Expiry checking                ->  Not-before + freshness + expiry

Key possession                 ->  Key + protected-context binding

Generic replay handling        ->  Challenge/capability/presentation/
                                   concurrency separation

Implicit version compatibility ->  Explicit version separation

Limited adversarial coverage   ->  100-test hardened suite

SQLite state-machine demo      ->  Explicit rollback limitation

Broad security wording         ->  Exact implementation boundaries
```

---

# Purpose of This Repository

The purpose of Implementation Reference Version 2 is not simply to increase the number of tests.

It is to make the architecture more falsifiable and easier to scrutinize.

The implementation provides executable material for examining:

```text
what is signed
what is independently verified
what remains non-effective
where freshness enters
what becomes single-use
how the exact consequence is bound
what causes rejection
what must occur before effectuation
what can be implemented portably
what requires protected platform integration
```

The repository is intended to support:

* protocol review;
* security analysis;
* interoperability discussion;
* independent implementation;
* adversarial testing;
* operating-system architecture discussion; and
* standards-oriented technical evaluation.

It does not claim IETF endorsement, EU endorsement, Apple endorsement, platform certification, or production-device certification.

---

# Central Principle

> **Computation may generate or prepare an operation, but computation is not authority.**

> **A consequential operation does not become externally effective until the Finality Sink verifies the complete, current, effect-specific authorization state immediately before effectuation.**

## License, Copyright, and Patent Rights

Copyright © 2026 Sangam Kumar Das. All rights reserved except as expressly licensed below.

### Creative Commons License

Except for material subject to the IETF Trust Legal Provisions or third-party rights, the copyrightable repository materials designated by the author for public reuse are made available under the:

**Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0)**

https://creativecommons.org/licenses/by-nc/4.0/

Under that license, the covered material may be copied, redistributed, adapted, and used for research, education, technical evaluation, interoperability analysis, standards discussion, academic study, and other permitted non-commercial purposes, provided that appropriate attribution is given and the applicable license conditions are followed.

Commercial use is not authorized by the CC BY-NC 4.0 license.

### Patent Rights Are Not Licensed

**The CC BY-NC 4.0 license is a copyright license only. It does not grant any patent license.**

Nothing in this repository, including publication of source code, reference implementations, test vectors, schemas, algorithms, diagrams, architectural descriptions, Internet-Draft source files, benchmark material, examples, or documentation, shall be interpreted as:

* granting an express or implied license under any patent or patent application;
* waiving, abandoning, dedicating, disclaiming, exhausting, or otherwise surrendering any patent right;
* granting a covenant not to sue;
* authorizing commercial implementation of technology covered by an applicable patent claim;
* representing that implementation of the material is free of third-party or author-held patent rights; or
* creating an estoppel against enforcement of applicable patent rights.

Patent rights, including rights arising from pending, published, future, continuation, divisional, national-phase, regional, or granted patent applications relating to the disclosed technology, are expressly reserved to the extent permitted by applicable law.

Where implementation of technology described or demonstrated in this repository would practice an enforceable patent claim, a separate patent license may be required.

### Reference Implementation Does Not Equal Patent Permission

The purpose of the runnable implementation is to perm

