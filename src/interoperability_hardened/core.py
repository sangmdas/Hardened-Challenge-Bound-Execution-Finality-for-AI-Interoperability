from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from . import cbor, cose

PROFILE_VERSION = 2
MAX_ACT_LIFETIME = 300
DEFAULT_CHALLENGE_TTL = 5
MAX_CHALLENGE_TTL = 30
REQUIRED_PREDICATES = (
    "destination", "freshness", "policy", "requester", "resource", "revocation", "scope", "user-intent"
)

class Denied(ValueError):
    def __init__(self, code: str): self.code=code; super().__init__(code)

def digest(data: bytes) -> bytes: return hashlib.sha256(data).digest()
def key_thumbprint(key: Ed25519PublicKey) -> bytes:
    return digest(key.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))

def _nonempty(value: object, name: str) -> str:
    if not isinstance(value,str) or not value or len(value)>512: raise Denied(f"invalid_{name}")
    return value

def _uint(value: object, name: str) -> int:
    if not isinstance(value,int) or isinstance(value,bool) or value<0 or value>0x7FFF_FFFF_FFFF_FFFF: raise Denied(f"invalid_{name}")
    return value

def _bytes(value: object, name: str, min_len: int, max_len: int) -> bytes:
    if not isinstance(value,bytes) or not (min_len<=len(value)<=max_len): raise Denied(f"invalid_{name}")
    return value

def _exact_map(value: object, keys: set[int], name: str) -> dict:
    if not isinstance(value,dict) or set(value)!=keys: raise Denied(f"invalid_{name}_schema")
    return value

@dataclass(frozen=True)
class CandidateAct:
    requester: str; action: str; resource_digest: bytes; destination: str; destination_app: str
    finality_sink: str; boundary: str; session_id: str; user_intent_digest: bytes
    policy_version: int; security_epoch: int; revocation_epoch: int; nonce: bytes
    issued_at: int; expires_at: int; act_id: str
    def validate(self) -> None:
        for name in ("requester","destination","destination_app","finality_sink","boundary","session_id","act_id"):
            _nonempty(getattr(self,name),name)
        if self.action not in {"message.send","file.export","app.dispatch"}: raise Denied("unsupported_action")
        _bytes(self.resource_digest,"resource_digest",32,32); _bytes(self.user_intent_digest,"user_intent_digest",32,32); _bytes(self.nonce,"nonce",16,64)
        for name in ("policy_version","security_epoch","revocation_epoch","issued_at","expires_at"): _uint(getattr(self,name),name)
        if self.expires_at<=self.issued_at or self.expires_at-self.issued_at>MAX_ACT_LIFETIME: raise Denied("invalid_validity_window")
    def encode(self) -> bytes:
        self.validate()
        return cbor.dumps({1:PROFILE_VERSION,2:self.act_id,3:self.requester,4:self.action,5:self.resource_digest,6:self.destination,7:self.destination_app,8:self.finality_sink,9:self.boundary,10:self.session_id,11:self.user_intent_digest,12:self.policy_version,13:self.security_epoch,14:self.revocation_epoch,15:self.nonce,16:self.issued_at,17:self.expires_at})
    @property
    def commitment(self) -> bytes: return digest(self.encode())

@dataclass(frozen=True)
class ActualEffect:
    requester: str; action: str; resource: bytes; destination: str; destination_app: str
    finality_sink: str; boundary: str; session_id: str; user_intent_digest: bytes
    policy_version: int; security_epoch: int; revocation_epoch: int; nonce: bytes
    issued_at: int; expires_at: int; act_id: str
    def reconstruct(self) -> CandidateAct:
        if not isinstance(self.resource,bytes): raise Denied("invalid_resource")
        return CandidateAct(self.requester,self.action,digest(self.resource),self.destination,self.destination_app,self.finality_sink,self.boundary,self.session_id,self.user_intent_digest,self.policy_version,self.security_epoch,self.revocation_epoch,self.nonce,self.issued_at,self.expires_at,self.act_id)

@dataclass(frozen=True)
class PolicyState:
    version: int; security_epoch: int; revocation_epoch: int
    allowed_actions: frozenset[str]; allowed_destination_apps: frozenset[str]

@dataclass(frozen=True)
class AuthorityBundle:
    lavr: bytes; capability: bytes

@dataclass(frozen=True)
class VerifiedAuthority:
    lavr: dict; capability: dict; cap_id: bytes; actual_commitment: bytes; validator_kid: bytes

class ProtectedState:
    """Crash-consistent reference state.

    IMPORTANT: SQLite is not rollback-resistant trusted storage. A production
    platform MUST map this API to rollback-protected state or an equivalent
    trusted service if rollback resistance is required by the threat model.
    """
    def __init__(self,path: str):
        self.db=sqlite3.connect(path,check_same_thread=False,isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL"); self.db.execute("PRAGMA synchronous=FULL"); self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS issued(
          cap_id BLOB PRIMARY KEY, act_id TEXT NOT NULL, nonce BLOB NOT NULL UNIQUE,
          requester TEXT NOT NULL, commitment BLOB NOT NULL, issued INTEGER NOT NULL,
          expires INTEGER NOT NULL, state TEXT NOT NULL);
        CREATE UNIQUE INDEX IF NOT EXISTS issued_act_id_unique ON issued(act_id);
        CREATE TABLE IF NOT EXISTS revoked(subject TEXT PRIMARY KEY, epoch INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS challenges(
          challenge_id BLOB PRIMARY KEY, challenge_nonce BLOB NOT NULL UNIQUE, cap_id BLOB NOT NULL,
          capability_digest BLOB NOT NULL, effect_commitment BLOB NOT NULL, sink_id TEXT NOT NULL,
          boundary TEXT NOT NULL, channel_binding_digest BLOB NOT NULL, issued INTEGER NOT NULL,
          expires INTEGER NOT NULL, state TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS effects(
          act_id TEXT PRIMARY KEY, action TEXT NOT NULL, destination TEXT NOT NULL,
          resource BLOB NOT NULL, committed_at INTEGER NOT NULL);
        """)
        self.lock=threading.Lock()
    def record_issued(self,cap_id: bytes,act: CandidateAct,issued_at: int) -> None:
        with self.lock:
            try:
                self.db.execute("INSERT INTO issued VALUES(?,?,?,?,?,?,?,'ISSUED')",(cap_id,act.act_id,act.nonce,act.requester,act.commitment,issued_at,act.expires_at))
            except sqlite3.IntegrityError as exc: raise Denied("nonce_or_act_reuse") from exc
    def record_challenge(self,token: dict) -> None:
        with self.lock:
            try:
                self.db.execute("INSERT INTO challenges VALUES(?,?,?,?,?,?,?,?,?,?,'ISSUED')",(token[2],token[3],token[11],token[4],token[5],token[6],token[7],token[8],token[9],token[10]))
            except sqlite3.IntegrityError as exc: raise Denied("challenge_reuse") from exc
    def revoke(self,subject: str,epoch: int) -> None:
        _nonempty(subject,"subject"); _uint(epoch,"revocation_epoch")
        with self.lock: self.db.execute("INSERT INTO revoked VALUES(?,?) ON CONFLICT(subject) DO UPDATE SET epoch=max(epoch,excluded.epoch)",(subject,epoch))
    def is_revoked(self,subject: str,capability_epoch: int) -> bool:
        row=self.db.execute("SELECT epoch FROM revoked WHERE subject=?",(subject,)).fetchone(); return bool(row and row[0]>=capability_epoch)
    def assert_issued(self,cap_id: bytes,act: CandidateAct,cap_issued: int) -> None:
        row=self.db.execute("SELECT act_id,nonce,requester,commitment,issued,expires,state FROM issued WHERE cap_id=?",(cap_id,)).fetchone()
        if not row: raise Denied("authority_unknown")
        expected=(act.act_id,act.nonce,act.requester,act.commitment,cap_issued,act.expires_at,"ISSUED")
        if row!=expected: raise Denied("authority_state_mismatch")
    def finalize(self,cap_id: bytes,challenge: dict,effect: ActualEffect,current: PolicyState,now: int) -> None:
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                cap=self.db.execute("SELECT state,requester,expires FROM issued WHERE cap_id=?",(cap_id,)).fetchone()
                if not cap or cap[0]!="ISSUED": raise Denied("authority_consumed_or_unknown")
                if now<challenge[9]: raise Denied("challenge_not_yet_valid")
                if now>challenge[10]: raise Denied("challenge_expired")
                ch=self.db.execute("SELECT challenge_nonce,cap_id,capability_digest,effect_commitment,sink_id,boundary,channel_binding_digest,issued,expires,state FROM challenges WHERE challenge_id=?",(challenge[2],)).fetchone()
                expected=(challenge[3],challenge[11],challenge[4],challenge[5],challenge[6],challenge[7],challenge[8],challenge[9],challenge[10],"ISSUED")
                if ch!=expected: raise Denied("challenge_consumed_or_mismatch")
                if now>cap[2]: raise Denied("authority_expired")
                revoked=self.db.execute("SELECT epoch FROM revoked WHERE subject=?",(cap[1],)).fetchone()
                if revoked and revoked[0]>=current.revocation_epoch: raise Denied("authority_revoked")
                if (effect.policy_version,effect.security_epoch,effect.revocation_epoch)!=(current.version,current.security_epoch,current.revocation_epoch): raise Denied("stale_governance_state")
                cur=self.db.execute("UPDATE issued SET state='COMMITTING' WHERE cap_id=? AND state='ISSUED'",(cap_id,))
                if cur.rowcount!=1: raise Denied("authority_race")
                chcur=self.db.execute("UPDATE challenges SET state='CONSUMING' WHERE challenge_id=? AND state='ISSUED'",(challenge[2],))
                if chcur.rowcount!=1: raise Denied("challenge_race")
                self.db.execute("INSERT INTO effects VALUES(?,?,?,?,?)",(effect.act_id,effect.action,effect.destination,effect.resource,now))
                self.db.execute("UPDATE challenges SET state='CONSUMED' WHERE challenge_id=?",(challenge[2],))
                self.db.execute("UPDATE issued SET state='CONSUMED' WHERE cap_id=?",(cap_id,))
                self.db.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self.db.execute("ROLLBACK"); raise Denied("duplicate_effect") from exc
            except Exception:
                self.db.execute("ROLLBACK"); raise
    def effect_count(self)->int: return int(self.db.execute("SELECT count(*) FROM effects").fetchone()[0])

class ProtectedValidator:
    def __init__(self,signing_key: Ed25519PrivateKey,kid: bytes,state: ProtectedState,policy: PolicyState,requester_keys: dict[str,Ed25519PublicKey]):
        self.key=signing_key; self.kid=kid; self.state=state; self.policy=policy; self.requester_keys=requester_keys
    def prepare(self,act: CandidateAct,user_intent_verified: bool,now: int|None=None) -> AuthorityBundle:
        now=int(time.time()) if now is None else now; act.validate()
        if act.requester not in self.requester_keys: raise Denied("unknown_requester")
        if act.action not in self.policy.allowed_actions or act.destination_app not in self.policy.allowed_destination_apps: raise Denied("policy_denied")
        if user_intent_verified is not True: raise Denied("user_intent_not_verified")
        if (act.policy_version,act.security_epoch,act.revocation_epoch)!=(self.policy.version,self.policy.security_epoch,self.policy.revocation_epoch): raise Denied("stale_governance_state")
        if now<act.issued_at: raise Denied("candidate_not_yet_valid")
        if now>act.expires_at: raise Denied("candidate_expired")
        if self.state.is_revoked(act.requester,act.revocation_epoch): raise Denied("requester_revoked")
        commitment=act.commitment; receipt_id=secrets.token_bytes(16)
        lavr_payload=cbor.dumps({1:PROFILE_VERSION,2:receipt_id,3:commitment,4:act.requester,5:act.nonce,6:act.policy_version,7:act.security_epoch,8:act.revocation_epoch,9:act.finality_sink,10:act.boundary,11:now,12:list(REQUIRED_PREDICATES)})
        lavr=cose.sign1(lavr_payload,self.key,self.kid); cap_id=secrets.token_bytes(16)
        capability_payload=cbor.dumps({1:PROFILE_VERSION,2:cap_id,3:commitment,4:digest(lavr),5:act.requester,6:key_thumbprint(self.requester_keys[act.requester]),7:act.finality_sink,8:act.boundary,9:act.nonce,10:act.policy_version,11:act.security_epoch,12:act.revocation_epoch,13:now,14:act.expires_at,15:1})
        capability=cose.sign1(capability_payload,self.key,self.kid); self.state.record_issued(cap_id,act,now)
        return AuthorityBundle(lavr,capability)

class FinalitySink:
    def __init__(self,sink_id: str,boundary: str,validator_keys: dict[bytes,Ed25519PublicKey],requester_keys: dict[bytes,Ed25519PublicKey],state: ProtectedState,policy: PolicyState|Callable[[],PolicyState]):
        self.sink_id=_nonempty(sink_id,"sink_id"); self.boundary=_nonempty(boundary,"boundary"); self.validator_keys=validator_keys; self.requester_keys=requester_keys; self.state=state
        self._policy_provider=policy if callable(policy) else (lambda: policy)
    def _current_policy(self)->PolicyState: return self._policy_provider()
    def _validate_authority(self,effect: ActualEffect,bundle: AuthorityBundle,now: int)->VerifiedAuthority:
        try:
            lavr_raw,lavr_kid=cose.verify1(bundle.lavr,self.validator_keys); cap_raw,cap_kid=cose.verify1(bundle.capability,self.validator_keys)
            lavr=_exact_map(cbor.loads(lavr_raw),set(range(1,13)),"lavr")
            cap=_exact_map(cbor.loads(cap_raw),set(range(1,16)),"capability")
        except (ValueError,KeyError,TypeError) as exc:
            if isinstance(exc,Denied): raise
            raise Denied("invalid_authority") from exc
        if lavr_kid!=cap_kid: raise Denied("validator_key_mismatch")
        if lavr[1]!=PROFILE_VERSION or cap[1]!=PROFILE_VERSION: raise Denied("unsupported_profile_version")
        _bytes(lavr[2],"receipt_id",16,32); _bytes(lavr[3],"lavr_commitment",32,32); _nonempty(lavr[4],"lavr_requester"); _bytes(lavr[5],"lavr_nonce",16,64)
        for k,n in ((6,"lavr_policy_version"),(7,"lavr_security_epoch"),(8,"lavr_revocation_epoch"),(11,"lavr_validated_at")): _uint(lavr[k],n)
        _nonempty(lavr[9],"lavr_sink"); _nonempty(lavr[10],"lavr_boundary")
        if not isinstance(lavr[12],list) or tuple(lavr[12])!=REQUIRED_PREDICATES: raise Denied("lavr_predicate_mismatch")
        _bytes(cap[2],"capability_id",16,32); _bytes(cap[3],"capability_commitment",32,32); _bytes(cap[4],"lavr_digest",32,32); _nonempty(cap[5],"capability_requester"); _bytes(cap[6],"requester_key_thumbprint",32,32)
        _nonempty(cap[7],"capability_sink"); _nonempty(cap[8],"capability_boundary"); _bytes(cap[9],"capability_nonce",16,64)
        for k,n in ((10,"capability_policy_version"),(11,"capability_security_epoch"),(12,"capability_revocation_epoch"),(13,"capability_issued_at"),(14,"capability_expires_at"),(15,"permitted_effect_count")): _uint(cap[k],n)
        if cap[15]!=1: raise Denied("invalid_permitted_effect_count")
        act=effect.reconstruct(); act.validate(); actual=act.commitment; current=self._current_policy()
        if cap[4]!=digest(bundle.lavr) or lavr[3]!=cap[3] or cap[3]!=actual: raise Denied("authority_binding_mismatch")
        if not (lavr[4]==cap[5]==effect.requester): raise Denied("requester_binding_mismatch")
        if not (lavr[5]==cap[9]==effect.nonce): raise Denied("nonce_binding_mismatch")
        if not (lavr[9]==cap[7]==effect.finality_sink==self.sink_id and lavr[10]==cap[8]==effect.boundary==self.boundary): raise Denied("wrong_finality_boundary")
        expected_epochs=(effect.policy_version,effect.security_epoch,effect.revocation_epoch)
        if (lavr[6],lavr[7],lavr[8])!=expected_epochs or (cap[10],cap[11],cap[12])!=expected_epochs: raise Denied("authority_epoch_mismatch")
        if expected_epochs!=(current.version,current.security_epoch,current.revocation_epoch): raise Denied("stale_governance_state")
        if effect.action not in current.allowed_actions or effect.destination_app not in current.allowed_destination_apps: raise Denied("current_policy_denied")
        if lavr[11]!=cap[13]: raise Denied("authority_time_mismatch")
        if cap[14]!=effect.expires_at: raise Denied("authority_expiry_mismatch")
        if not (effect.issued_at<=lavr[11]<=effect.expires_at): raise Denied("invalid_validation_time")
        if now<cap[13]: raise Denied("authority_not_yet_valid")
        if now>cap[14]: raise Denied("authority_expired")
        self.state.assert_issued(cap[2],act,cap[13])
        if self.state.is_revoked(effect.requester,cap[12]): raise Denied("authority_revoked")
        return VerifiedAuthority(lavr,cap,cap[2],actual,cap_kid)
    def issue_challenge(self,effect: ActualEffect,bundle: AuthorityBundle,protected_channel_binding: bytes,now: int|None=None,ttl: int=DEFAULT_CHALLENGE_TTL)->bytes:
        now=int(time.time()) if now is None else now
        if not isinstance(protected_channel_binding,bytes) or len(protected_channel_binding)<16: raise Denied("missing_protected_channel_binding")
        if not isinstance(ttl,int) or isinstance(ttl,bool) or ttl<1 or ttl>MAX_CHALLENGE_TTL: raise Denied("invalid_challenge_ttl")
        verified=self._validate_authority(effect,bundle,now)
        token={1:PROFILE_VERSION,2:secrets.token_bytes(16),3:secrets.token_bytes(32),4:digest(bundle.capability),5:verified.actual_commitment,6:self.sink_id,7:self.boundary,8:digest(protected_channel_binding),9:now,10:now+ttl,11:verified.cap_id}
        self.state.record_challenge(token); return cbor.dumps(token)
    def finalize(self,effect: ActualEffect,bundle: AuthorityBundle,challenge_token: bytes,presentation: bytes,protected_channel_binding: bytes,now: int|None=None)->str:
        now=int(time.time()) if now is None else now
        if not isinstance(protected_channel_binding,bytes) or len(protected_channel_binding)<16: raise Denied("missing_protected_channel_binding")
        verified=self._validate_authority(effect,bundle,now)
        try: challenge=_exact_map(cbor.loads(challenge_token),set(range(1,12)),"challenge")
        except (ValueError,TypeError) as exc:
            if isinstance(exc,Denied): raise
            raise Denied("invalid_challenge") from exc
        if challenge[1]!=PROFILE_VERSION: raise Denied("unsupported_challenge_version")
        _bytes(challenge[2],"challenge_id",16,32); _bytes(challenge[3],"challenge_nonce",32,32); _bytes(challenge[4],"challenge_capability_digest",32,32); _bytes(challenge[5],"challenge_effect_commitment",32,32)
        _nonempty(challenge[6],"challenge_sink"); _nonempty(challenge[7],"challenge_boundary"); _bytes(challenge[8],"channel_binding_digest",32,32); _uint(challenge[9],"challenge_issued_at"); _uint(challenge[10],"challenge_expires_at"); _bytes(challenge[11],"challenge_capability_id",16,32)
        if challenge[10]<=challenge[9] or challenge[10]-challenge[9]>MAX_CHALLENGE_TTL: raise Denied("invalid_challenge_window")
        if now<challenge[9]: raise Denied("challenge_not_yet_valid")
        if now>challenge[10]: raise Denied("challenge_expired")
        expected=(digest(bundle.capability),verified.actual_commitment,self.sink_id,self.boundary,digest(protected_channel_binding),verified.cap_id)
        if (challenge[4],challenge[5],challenge[6],challenge[7],challenge[8],challenge[11])!=expected: raise Denied("challenge_context_mismatch")
        try:
            pop_raw,pop_kid=cose.verify1(presentation,self.requester_keys); pop=_exact_map(cbor.loads(pop_raw),set(range(1,11)),"presentation")
        except (ValueError,TypeError) as exc:
            if isinstance(exc,Denied): raise
            raise Denied("invalid_proof_of_possession") from exc
        if pop[1]!=PROFILE_VERSION: raise Denied("unsupported_presentation_version")
        if key_thumbprint(self.requester_keys[pop_kid])!=verified.capability[6]: raise Denied("requester_key_mismatch")
        exact={1:PROFILE_VERSION,2:digest(bundle.capability),3:verified.actual_commitment,4:effect.act_id,5:effect.nonce,6:challenge[2],7:challenge[3],8:self.sink_id,9:self.boundary,10:digest(protected_channel_binding)}
        if pop!=exact: raise Denied("proof_of_possession_mismatch")
        if self.state.is_revoked(effect.requester,verified.capability[12]): raise Denied("authority_revoked")
        current=self._current_policy(); self.state.finalize(verified.cap_id,challenge,effect,current,now); return "EFFECT_COMMITTED"

def create_presentation(capability: bytes,effect: ActualEffect,challenge_token: bytes,protected_channel_binding: bytes,requester_key: Ed25519PrivateKey,kid: bytes)->bytes:
    if not isinstance(protected_channel_binding,bytes) or len(protected_channel_binding)<16: raise Denied("missing_protected_channel_binding")
    try: challenge=_exact_map(cbor.loads(challenge_token),set(range(1,12)),"challenge")
    except (ValueError,TypeError) as exc:
        if isinstance(exc,Denied): raise
        raise Denied("invalid_challenge") from exc
    actual=effect.reconstruct().commitment
    payload=cbor.dumps({1:PROFILE_VERSION,2:digest(capability),3:actual,4:effect.act_id,5:effect.nonce,6:challenge[2],7:challenge[3],8:effect.finality_sink,9:effect.boundary,10:digest(protected_channel_binding)})
    return cose.sign1(payload,requester_key,kid)
