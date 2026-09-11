"""Minimal strict COSE_Sign1 Ed25519 profile."""
from __future__ import annotations
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from . import cbor
ALG=1; KID=4; EDDSA=-8
class COSEError(ValueError): pass

def sign1(payload: bytes, private_key: Ed25519PrivateKey, kid: bytes) -> bytes:
    if not isinstance(payload, bytes): raise COSEError("payload must be bytes")
    if not isinstance(kid, bytes) or not kid or len(kid)>64: raise COSEError("kid must contain 1..64 bytes")
    protected=cbor.dumps({ALG:EDDSA,KID:kid})
    sig=private_key.sign(cbor.dumps(["Signature1",protected,b"",payload]))
    return cbor.dumps([protected,{},payload,sig])

def verify1(token: bytes, keys: dict[bytes,Ed25519PublicKey]) -> tuple[bytes,bytes]:
    try: value=cbor.loads(token)
    except (cbor.CBORError,TypeError) as exc: raise COSEError("malformed COSE_Sign1") from exc
    if not isinstance(value,list) or len(value)!=4: raise COSEError("COSE_Sign1 must contain four elements")
    protected,unprotected,payload,signature=value
    if not all(isinstance(x,bytes) for x in (protected,payload,signature)) or not isinstance(unprotected,dict): raise COSEError("invalid COSE_Sign1 field types")
    if unprotected: raise COSEError("unprotected headers are not accepted")
    headers=cbor.loads(protected)
    if headers.get(ALG)!=EDDSA or set(headers)!={ALG,KID}: raise COSEError("unsupported or incomplete protected headers")
    kid=headers[KID]
    if not isinstance(kid,bytes) or kid not in keys: raise COSEError("unknown signing key")
    try: keys[kid].verify(signature,cbor.dumps(["Signature1",protected,b"",payload]))
    except InvalidSignature as exc: raise COSEError("invalid signature") from exc
    return payload,kid
