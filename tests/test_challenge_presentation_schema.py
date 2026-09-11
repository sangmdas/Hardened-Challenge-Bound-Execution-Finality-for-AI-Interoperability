from __future__ import annotations
from common import Harness,NOW,CHANNEL
from interoperability_hardened import cbor,cose
from interoperability_hardened.core import Denied,create_presentation,digest

class ChallengePresentationSchemaTests(Harness):
    def mutate_challenge(self,key,value=None,delete=False):
        ch=cbor.loads(self.challenge())
        if delete: del ch[key]
        else: ch[key]=value
        return cbor.dumps(ch)
    def test_challenge_extra_field_rejected(self):
        ch=self.mutate_challenge(99,'x')
        with self.assertRaisesRegex(Denied,'invalid_challenge_schema'): self.presentation(ch)
    def test_challenge_missing_field_rejected(self):
        ch=self.mutate_challenge(6,delete=True)
        with self.assertRaisesRegex(Denied,'invalid_challenge_schema'): self.presentation(ch)
    def test_challenge_capability_digest_rejected(self):
        ch=self.mutate_challenge(4,b'X'*32); pop=self.presentation(ch)
        with self.assertRaisesRegex(Denied,'challenge_context_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW)
    def test_challenge_effect_commitment_rejected(self):
        ch=self.mutate_challenge(5,b'X'*32); pop=self.presentation(ch)
        with self.assertRaisesRegex(Denied,'challenge_context_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW)
    def test_challenge_sink_rejected(self):
        ch=self.mutate_challenge(6,'urn:wrong'); pop=self.presentation(ch)
        with self.assertRaisesRegex(Denied,'challenge_context_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW)
    def test_challenge_boundary_rejected(self):
        ch=self.mutate_challenge(7,'wrong'); pop=self.presentation(ch)
        with self.assertRaisesRegex(Denied,'challenge_context_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW)
    def test_challenge_channel_binding_digest_rejected(self):
        ch=self.mutate_challenge(8,b'X'*32); pop=self.presentation(ch)
        with self.assertRaisesRegex(Denied,'challenge_context_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW)
    def test_challenge_cap_id_rejected(self):
        ch=self.mutate_challenge(11,b'X'*16); pop=self.presentation(ch)
        with self.assertRaisesRegex(Denied,'challenge_context_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW)
    def test_presentation_extra_field_rejected(self):
        ch=self.challenge(); raw,kid=cose.verify1(self.presentation(ch),{b'assistant-key-1':self.app_key.public_key()}); p=cbor.loads(raw); p[99]='x'; tok=cose.sign1(cbor.dumps(p),self.app_key,b'assistant-key-1')
        with self.assertRaisesRegex(Denied,'invalid_presentation_schema'): self.sink.finalize(self.effect,self.bundle,ch,tok,CHANNEL,NOW)
    def test_presentation_missing_field_rejected(self):
        ch=self.challenge(); raw,kid=cose.verify1(self.presentation(ch),{b'assistant-key-1':self.app_key.public_key()}); p=cbor.loads(raw); del p[6]; tok=cose.sign1(cbor.dumps(p),self.app_key,b'assistant-key-1')
        with self.assertRaisesRegex(Denied,'invalid_presentation_schema'): self.sink.finalize(self.effect,self.bundle,ch,tok,CHANNEL,NOW)
    def test_presentation_wrong_challenge_id_rejected(self):
        ch=self.challenge(); raw,_=cose.verify1(self.presentation(ch),{b'assistant-key-1':self.app_key.public_key()}); p=cbor.loads(raw); p[6]=b'X'*16; tok=cose.sign1(cbor.dumps(p),self.app_key,b'assistant-key-1')
        with self.assertRaisesRegex(Denied,'proof_of_possession_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,tok,CHANNEL,NOW)
    def test_presentation_wrong_challenge_nonce_rejected(self):
        ch=self.challenge(); raw,_=cose.verify1(self.presentation(ch),{b'assistant-key-1':self.app_key.public_key()}); p=cbor.loads(raw); p[7]=b'X'*32; tok=cose.sign1(cbor.dumps(p),self.app_key,b'assistant-key-1')
        with self.assertRaisesRegex(Denied,'proof_of_possession_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,tok,CHANNEL,NOW)
    def test_presentation_wrong_cap_digest_rejected(self):
        ch=self.challenge(); raw,_=cose.verify1(self.presentation(ch),{b'assistant-key-1':self.app_key.public_key()}); p=cbor.loads(raw); p[2]=b'X'*32; tok=cose.sign1(cbor.dumps(p),self.app_key,b'assistant-key-1')
        with self.assertRaisesRegex(Denied,'proof_of_possession_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,tok,CHANNEL,NOW)
    def test_presentation_wrong_effect_commitment_rejected(self):
        ch=self.challenge(); raw,_=cose.verify1(self.presentation(ch),{b'assistant-key-1':self.app_key.public_key()}); p=cbor.loads(raw); p[3]=b'X'*32; tok=cose.sign1(cbor.dumps(p),self.app_key,b'assistant-key-1')
        with self.assertRaisesRegex(Denied,'proof_of_possession_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,tok,CHANNEL,NOW)
    def test_presentation_wrong_sink_rejected(self):
        ch=self.challenge(); raw,_=cose.verify1(self.presentation(ch),{b'assistant-key-1':self.app_key.public_key()}); p=cbor.loads(raw); p[8]='urn:wrong'; tok=cose.sign1(cbor.dumps(p),self.app_key,b'assistant-key-1')
        with self.assertRaisesRegex(Denied,'proof_of_possession_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,tok,CHANNEL,NOW)
    def test_presentation_wrong_boundary_rejected(self):
        ch=self.challenge(); raw,_=cose.verify1(self.presentation(ch),{b'assistant-key-1':self.app_key.public_key()}); p=cbor.loads(raw); p[9]='wrong'; tok=cose.sign1(cbor.dumps(p),self.app_key,b'assistant-key-1')
        with self.assertRaisesRegex(Denied,'proof_of_possession_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,tok,CHANNEL,NOW)
    def test_presentation_wrong_channel_binding_rejected(self):
        ch=self.challenge(); raw,_=cose.verify1(self.presentation(ch),{b'assistant-key-1':self.app_key.public_key()}); p=cbor.loads(raw); p[10]=b'X'*32; tok=cose.sign1(cbor.dumps(p),self.app_key,b'assistant-key-1')
        with self.assertRaisesRegex(Denied,'proof_of_possession_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,tok,CHANNEL,NOW)
