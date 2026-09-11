from __future__ import annotations
from dataclasses import replace
from common import Harness,NOW,CHANNEL
from interoperability_hardened import cbor,cose
from interoperability_hardened.core import AuthorityBundle,Denied,digest,create_presentation

class StrictSignedFieldTests(Harness):
    def decoded(self):
        lr,_=cose.verify1(self.bundle.lavr,{b'os-validator-1':self.os_key.public_key()}); cr,_=cose.verify1(self.bundle.capability,{b'os-validator-1':self.os_key.public_key()}); return cbor.loads(lr),cbor.loads(cr)
    def resign_cap(self,cap):
        ct=cose.sign1(cbor.dumps(cap),self.os_key,b'os-validator-1'); return AuthorityBundle(self.bundle.lavr,ct)
    def resign_both(self,lavr,cap):
        lt=cose.sign1(cbor.dumps(lavr),self.os_key,b'os-validator-1'); cap=dict(cap); cap[4]=digest(lt); ct=cose.sign1(cbor.dumps(cap),self.os_key,b'os-validator-1'); return AuthorityBundle(lt,ct)
    def assert_denied_bundle(self,bundle,pattern=None):
        cm=self.assertRaisesRegex(Denied,pattern) if pattern else self.assertRaises(Denied)
        with cm:self.sink.issue_challenge(self.effect,bundle,CHANNEL,NOW)
    def test_cap_requester_crosscheck(self):
        l,c=self.decoded(); c[5]='different'; self.assert_denied_bundle(self.resign_cap(c),'requester_binding_mismatch')
    def test_cap_nonce_crosscheck(self):
        l,c=self.decoded(); c[9]=b'X'*24; self.assert_denied_bundle(self.resign_cap(c),'nonce_binding_mismatch')
    def test_cap_policy_epoch_crosscheck(self):
        l,c=self.decoded(); c[10]=999; self.assert_denied_bundle(self.resign_cap(c),'authority_epoch_mismatch')
    def test_cap_security_epoch_crosscheck(self):
        l,c=self.decoded(); c[11]=999; self.assert_denied_bundle(self.resign_cap(c),'authority_epoch_mismatch')
    def test_cap_revocation_epoch_crosscheck(self):
        l,c=self.decoded(); c[12]=999; self.assert_denied_bundle(self.resign_cap(c),'authority_epoch_mismatch')
    def test_cap_use_count_must_be_one(self):
        l,c=self.decoded(); c[15]=2; self.assert_denied_bundle(self.resign_cap(c),'invalid_permitted_effect_count')
    def test_cap_sink_crosscheck(self):
        l,c=self.decoded(); c[7]='urn:wrong'; self.assert_denied_bundle(self.resign_cap(c),'wrong_finality_boundary')
    def test_cap_boundary_crosscheck(self):
        l,c=self.decoded(); c[8]='wrong'; self.assert_denied_bundle(self.resign_cap(c),'wrong_finality_boundary')
    def test_cap_expiry_crosscheck(self):
        l,c=self.decoded(); c[14]+=1; self.assert_denied_bundle(self.resign_cap(c),'authority_expiry_mismatch')
    def test_cap_future_issue_time_rejected(self):
        l,c=self.decoded(); l[11]=NOW+4; c[13]=NOW+4; b=self.resign_both(l,c); self.assert_denied_bundle(b,'authority_not_yet_valid|authority_state_mismatch')
    def test_cap_missing_field_rejected(self):
        l,c=self.decoded(); del c[5]; self.assert_denied_bundle(self.resign_cap(c),'invalid_capability_schema')
    def test_cap_extra_field_rejected(self):
        l,c=self.decoded(); c[99]='x'; self.assert_denied_bundle(self.resign_cap(c),'invalid_capability_schema')
    def test_lavr_requester_crosscheck(self):
        l,c=self.decoded(); l[4]='different'; self.assert_denied_bundle(self.resign_both(l,c),'requester_binding_mismatch')
    def test_lavr_nonce_crosscheck(self):
        l,c=self.decoded(); l[5]=b'Z'*24; self.assert_denied_bundle(self.resign_both(l,c),'nonce_binding_mismatch')
    def test_lavr_policy_epoch_crosscheck(self):
        l,c=self.decoded(); l[6]=999; self.assert_denied_bundle(self.resign_both(l,c),'authority_epoch_mismatch')
    def test_lavr_security_epoch_crosscheck(self):
        l,c=self.decoded(); l[7]=999; self.assert_denied_bundle(self.resign_both(l,c),'authority_epoch_mismatch')
    def test_lavr_revocation_epoch_crosscheck(self):
        l,c=self.decoded(); l[8]=999; self.assert_denied_bundle(self.resign_both(l,c),'authority_epoch_mismatch')
    def test_lavr_sink_crosscheck(self):
        l,c=self.decoded(); l[9]='urn:wrong'; self.assert_denied_bundle(self.resign_both(l,c),'wrong_finality_boundary')
    def test_lavr_boundary_crosscheck(self):
        l,c=self.decoded(); l[10]='wrong'; self.assert_denied_bundle(self.resign_both(l,c),'wrong_finality_boundary')
    def test_lavr_predicates_required(self):
        l,c=self.decoded(); l[12]=[]; self.assert_denied_bundle(self.resign_both(l,c),'lavr_predicate_mismatch')
    def test_lavr_missing_field_rejected(self):
        l,c=self.decoded(); del l[4]; self.assert_denied_bundle(self.resign_both(l,c),'invalid_lavr_schema')
    def test_lavr_extra_field_rejected(self):
        l,c=self.decoded(); l[99]='x'; self.assert_denied_bundle(self.resign_both(l,c),'invalid_lavr_schema')
    def test_lavr_capability_validation_time_must_match(self):
        l,c=self.decoded(); l[11]=NOW+1; self.assert_denied_bundle(self.resign_both(l,c),'authority_time_mismatch')
    def test_validator_kid_mismatch_rejected(self):
        l,c=self.decoded(); other=self.other_key
        lt=cose.sign1(cbor.dumps(l),other,b'other-validator'); c[4]=digest(lt); ct=cose.sign1(cbor.dumps(c),self.os_key,b'os-validator-1')
        from interoperability_hardened.core import FinalitySink
        sink=FinalitySink(self.sink.sink_id,self.sink.boundary,{b'os-validator-1':self.os_key.public_key(),b'other-validator':other.public_key()},self.sink.requester_keys,self.state,self.policy)
        with self.assertRaisesRegex(Denied,'validator_key_mismatch'): sink.issue_challenge(self.effect,AuthorityBundle(lt,ct),CHANNEL,NOW)
