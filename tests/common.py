from __future__ import annotations
import hashlib, os, tempfile, unittest
from dataclasses import replace
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from interoperability_hardened.core import ActualEffect,CandidateAct,FinalitySink,PolicyState,ProtectedState,ProtectedValidator,create_presentation
NOW=1_800_000_000
RESOURCE=b'confidential tax return bytes'
CHANNEL=b'platform-audit-token-or-local-channel-binding-0001'
class Harness(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.NamedTemporaryFile(delete=False); self.tmp.close()
        self.state=ProtectedState(self.tmp.name)
        self.os_key=Ed25519PrivateKey.generate(); self.app_key=Ed25519PrivateKey.generate(); self.other_key=Ed25519PrivateKey.generate()
        self.policy=PolicyState(7,11,3,frozenset({'message.send'}),frozenset({'system.messages'}))
        self.act=CandidateAct('assistant.example','message.send',hashlib.sha256(RESOURCE).digest(),'alice@example.com','system.messages','urn:device:sink:messages','messages-send-boundary','session-123',bytes.fromhex('aa'*32),7,11,3,bytes.fromhex('bb'*24),NOW,NOW+30,'act-123')
        self.validator=ProtectedValidator(self.os_key,b'os-validator-1',self.state,self.policy,{'assistant.example':self.app_key.public_key()})
        self.bundle=self.validator.prepare(self.act,True,NOW)
        self.effect=ActualEffect('assistant.example','message.send',RESOURCE,'alice@example.com','system.messages','urn:device:sink:messages','messages-send-boundary','session-123',bytes.fromhex('aa'*32),7,11,3,bytes.fromhex('bb'*24),NOW,NOW+30,'act-123')
        self.sink=FinalitySink('urn:device:sink:messages','messages-send-boundary',{b'os-validator-1':self.os_key.public_key()},{b'assistant-key-1':self.app_key.public_key(),b'attacker-key':self.other_key.public_key()},self.state,self.policy)
    def tearDown(self):
        try:self.state.db.close()
        except Exception:pass
        for suffix in ('','-wal','-shm'):
            try:os.unlink(self.tmp.name+suffix)
            except OSError:pass
    def challenge(self,effect=None,bundle=None,channel=CHANNEL,now=NOW,ttl=5):
        return self.sink.issue_challenge(effect or self.effect,bundle or self.bundle,channel,now,ttl)
    def presentation(self,challenge,effect=None,bundle=None,key=None,kid=b'assistant-key-1',channel=CHANNEL):
        return create_presentation((bundle or self.bundle).capability,effect or self.effect,challenge,channel,key or self.app_key,kid)
    def finalize(self,challenge=None,presentation=None,effect=None,bundle=None,channel=CHANNEL,now=NOW):
        effect=effect or self.effect; bundle=bundle or self.bundle; challenge=challenge or self.challenge(effect,bundle,channel,now)
        presentation=presentation or self.presentation(challenge,effect,bundle,channel=channel)
        return self.sink.finalize(effect,bundle,challenge,presentation,channel,now)
