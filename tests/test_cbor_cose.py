import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from interoperability_hardened import cbor, cose

class CBORTests(unittest.TestCase):
    def test_round_trip_primitives(self):
        for value in [None,True,False,0,1,23,24,255,256,-1,-25,b'',b'abc','hello',[1,'x'],{1:'a',2:b'b'}]: self.assertEqual(cbor.loads(cbor.dumps(value)),value)
    def test_deterministic_map_order(self): self.assertEqual(cbor.dumps({2:'b',1:'a'}),cbor.dumps({1:'a',2:'b'}))
    def test_trailing_data_rejected(self):
        with self.assertRaises(cbor.CBORError): cbor.loads(cbor.dumps(1)+b'\x00')
    def test_truncated_bytes_rejected(self):
        with self.assertRaises(cbor.CBORError): cbor.loads(b'\x43ab')
    def test_nonminimal_uint8_rejected(self):
        with self.assertRaises(cbor.CBORError): cbor.loads(b'\x18\x17')
    def test_indefinite_array_rejected(self):
        with self.assertRaises(cbor.CBORError): cbor.loads(b'\x9f\x01\xff')
    def test_float_rejected(self):
        with self.assertRaises(cbor.CBORError): cbor.loads(b'\xfb'+b'\x00'*8)
    def test_tag_rejected(self):
        with self.assertRaises(cbor.CBORError): cbor.loads(b'\xc0\x00')
    def test_invalid_utf8_rejected(self):
        with self.assertRaises(cbor.CBORError): cbor.loads(b'\x61\xff')
    def test_duplicate_map_key_rejected(self):
        with self.assertRaises(cbor.CBORError): cbor.loads(b'\xa2\x01\x01\x01\x02')
    def test_nondeterministic_map_order_rejected(self):
        with self.assertRaises(cbor.CBORError): cbor.loads(b'\xa2\x02\x00\x01\x00')
    def test_unsupported_python_float_dump_rejected(self):
        with self.assertRaises(cbor.CBORError): cbor.dumps(1.2)
    def test_uint64_max_roundtrip(self): self.assertEqual(cbor.loads(cbor.dumps(2**64-1)),2**64-1)
    def test_uint64_overflow_rejected(self):
        with self.assertRaises(cbor.CBORError): cbor.dumps(2**64)

class COSETests(unittest.TestCase):
    def setUp(self): self.k=Ed25519PrivateKey.generate(); self.other=Ed25519PrivateKey.generate(); self.kid=b'k1'
    def test_valid_signature(self):
        t=cose.sign1(b'payload',self.k,self.kid); self.assertEqual(cose.verify1(t,{self.kid:self.k.public_key()}),(b'payload',self.kid))
    def test_empty_kid_rejected(self):
        with self.assertRaises(cose.COSEError): cose.sign1(b'x',self.k,b'')
    def test_long_kid_rejected(self):
        with self.assertRaises(cose.COSEError): cose.sign1(b'x',self.k,b'x'*65)
    def test_unknown_kid_rejected(self):
        t=cose.sign1(b'x',self.k,self.kid)
        with self.assertRaises(cose.COSEError): cose.verify1(t,{b'other':self.k.public_key()})
    def test_wrong_public_key_rejected(self):
        t=cose.sign1(b'x',self.k,self.kid)
        with self.assertRaises(cose.COSEError): cose.verify1(t,{self.kid:self.other.public_key()})
    def test_tampered_payload_rejected(self):
        t=cbor.loads(cose.sign1(b'x',self.k,self.kid)); t[2]=b'y'
        with self.assertRaises(cose.COSEError): cose.verify1(cbor.dumps(t),{self.kid:self.k.public_key()})
    def test_tampered_signature_rejected(self):
        t=cbor.loads(cose.sign1(b'x',self.k,self.kid)); t[3]=bytes([t[3][0]^1])+t[3][1:]
        with self.assertRaises(cose.COSEError): cose.verify1(cbor.dumps(t),{self.kid:self.k.public_key()})
    def test_unprotected_header_rejected(self):
        t=cbor.loads(cose.sign1(b'x',self.k,self.kid)); t[1]={99:1}
        with self.assertRaises(cose.COSEError): cose.verify1(cbor.dumps(t),{self.kid:self.k.public_key()})
    def test_malformed_array_rejected(self):
        with self.assertRaises(cose.COSEError): cose.verify1(cbor.dumps([b'a']),{self.kid:self.k.public_key()})
    def test_nonbytes_payload_rejected(self):
        protected=cbor.dumps({1:-8,4:self.kid}); t=cbor.dumps([protected,{},'text',b'x'*64])
        with self.assertRaises(cose.COSEError): cose.verify1(t,{self.kid:self.k.public_key()})
