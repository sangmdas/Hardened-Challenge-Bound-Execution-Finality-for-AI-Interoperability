from __future__ import annotations
from dataclasses import replace
import threading
from common import Harness,NOW,RESOURCE,CHANNEL
from interoperability_hardened.core import Denied,FinalitySink,PolicyState,ProtectedState,ProtectedValidator,create_presentation

class HardenedFinalityTests(Harness):
    def test_success(self): self.assertEqual(self.finalize(),'EFFECT_COMMITTED')
    def test_capability_replay_rejected(self):
        ch=self.challenge(); pop=self.presentation(ch); self.assertEqual(self.finalize(ch,pop),'EFFECT_COMMITTED')
        with self.assertRaises(Denied): self.sink.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW)
    def test_fresh_challenge_required(self):
        ch1=self.challenge(); pop1=self.presentation(ch1)
        ch2=self.challenge()
        with self.assertRaisesRegex(Denied,'proof_of_possession_mismatch'): self.sink.finalize(self.effect,self.bundle,ch2,pop1,CHANNEL,NOW)
    def test_wrong_requester_key_rejected(self):
        ch=self.challenge(); pop=self.presentation(ch,key=self.other_key,kid=b'attacker-key')
        with self.assertRaisesRegex(Denied,'requester_key_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW)
    def test_missing_channel_binding_rejected_at_challenge(self):
        with self.assertRaisesRegex(Denied,'missing_protected_channel_binding'): self.sink.issue_challenge(self.effect,self.bundle,b'',NOW)
    def test_missing_channel_binding_rejected_at_finalize(self):
        ch=self.challenge(); pop=self.presentation(ch)
        with self.assertRaisesRegex(Denied,'missing_protected_channel_binding'): self.sink.finalize(self.effect,self.bundle,ch,pop,b'',NOW)
    def test_wrong_channel_binding_rejected(self):
        ch=self.challenge(); pop=self.presentation(ch)
        with self.assertRaisesRegex(Denied,'challenge_context_mismatch'): self.sink.finalize(self.effect,self.bundle,ch,pop,b'other-protected-channel-binding-0000',NOW)
    def test_challenge_expiry_rejected(self):
        ch=self.challenge(ttl=2); pop=self.presentation(ch)
        with self.assertRaisesRegex(Denied,'challenge_expired'): self.sink.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW+3)
    def test_invalid_challenge_ttl_rejected(self):
        with self.assertRaisesRegex(Denied,'invalid_challenge_ttl'): self.challenge(ttl=31)
    def test_authority_expired_rejected(self):
        with self.assertRaisesRegex(Denied,'authority_expired'): self.challenge(now=NOW+31)
    def test_exact_authority_expiry_allowed(self):
        ch=self.challenge(now=NOW+30); pop=self.presentation(ch); self.assertEqual(self.sink.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW+30),'EFFECT_COMMITTED')
    def test_future_candidate_denied_by_validator(self):
        act=replace(self.act,nonce=b'F'*24,act_id='future',issued_at=NOW+1,expires_at=NOW+31)
        with self.assertRaisesRegex(Denied,'candidate_not_yet_valid'): self.validator.prepare(act,True,NOW)
    def test_revocation_after_challenge_rejected(self):
        ch=self.challenge(); pop=self.presentation(ch); self.state.revoke('assistant.example',3)
        with self.assertRaisesRegex(Denied,'authority_revoked'): self.sink.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW)
    def test_policy_change_after_challenge_rejected(self):
        current=[self.policy]
        sink=FinalitySink(self.sink.sink_id,self.sink.boundary,self.sink.validator_keys,self.sink.requester_keys,self.state,lambda:current[0])
        ch=sink.issue_challenge(self.effect,self.bundle,CHANNEL,NOW); pop=create_presentation(self.bundle.capability,self.effect,ch,CHANNEL,self.app_key,b'assistant-key-1')
        current[0]=replace(self.policy,version=8)
        with self.assertRaisesRegex(Denied,'stale_governance_state'): sink.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW)
    def test_policy_content_change_without_epoch_rejected(self):
        current=PolicyState(7,11,3,frozenset(),frozenset({'system.messages'}))
        sink=FinalitySink(self.sink.sink_id,self.sink.boundary,self.sink.validator_keys,self.sink.requester_keys,self.state,current)
        with self.assertRaisesRegex(Denied,'current_policy_denied'): sink.issue_challenge(self.effect,self.bundle,CHANNEL,NOW)
    def test_wrong_resource_rejected(self):
        e=replace(self.effect,resource=b'other')
        with self.assertRaisesRegex(Denied,'authority_binding_mismatch'): self.sink.issue_challenge(e,self.bundle,CHANNEL,NOW)
    def test_wrong_destination_rejected(self):
        e=replace(self.effect,destination='mallory@example.com')
        with self.assertRaisesRegex(Denied,'authority_binding_mismatch'): self.sink.issue_challenge(e,self.bundle,CHANNEL,NOW)
    def test_wrong_destination_app_rejected(self):
        e=replace(self.effect,destination_app='other.app')
        with self.assertRaisesRegex(Denied,'authority_binding_mismatch'): self.sink.issue_challenge(e,self.bundle,CHANNEL,NOW)
    def test_wrong_session_rejected(self):
        e=replace(self.effect,session_id='other-session')
        with self.assertRaisesRegex(Denied,'authority_binding_mismatch'): self.sink.issue_challenge(e,self.bundle,CHANNEL,NOW)
    def test_wrong_user_intent_digest_rejected(self):
        e=replace(self.effect,user_intent_digest=b'Z'*32)
        with self.assertRaisesRegex(Denied,'authority_binding_mismatch'): self.sink.issue_challenge(e,self.bundle,CHANNEL,NOW)
    def test_wrong_action_rejected(self):
        e=replace(self.effect,action='file.export')
        with self.assertRaisesRegex(Denied,'authority_binding_mismatch'): self.sink.issue_challenge(e,self.bundle,CHANNEL,NOW)
    def test_wrong_act_id_rejected(self):
        e=replace(self.effect,act_id='other-act')
        with self.assertRaisesRegex(Denied,'authority_binding_mismatch'): self.sink.issue_challenge(e,self.bundle,CHANNEL,NOW)
    def test_wrong_nonce_rejected(self):
        e=replace(self.effect,nonce=b'N'*24)
        with self.assertRaisesRegex(Denied,'authority_binding_mismatch'): self.sink.issue_challenge(e,self.bundle,CHANNEL,NOW)
    def test_wrong_sink_rejected(self):
        e=replace(self.effect,finality_sink='urn:wrong')
        with self.assertRaisesRegex(Denied,'authority_binding_mismatch|wrong_finality_boundary'): self.sink.issue_challenge(e,self.bundle,CHANNEL,NOW)
    def test_wrong_boundary_rejected(self):
        e=replace(self.effect,boundary='wrong-boundary')
        with self.assertRaisesRegex(Denied,'authority_binding_mismatch|wrong_finality_boundary'): self.sink.issue_challenge(e,self.bundle,CHANNEL,NOW)
    def test_wrong_policy_epoch_rejected(self):
        e=replace(self.effect,policy_version=8)
        with self.assertRaises(Denied): self.sink.issue_challenge(e,self.bundle,CHANNEL,NOW)
    def test_wrong_security_epoch_rejected(self):
        e=replace(self.effect,security_epoch=12)
        with self.assertRaises(Denied): self.sink.issue_challenge(e,self.bundle,CHANNEL,NOW)
    def test_wrong_revocation_epoch_rejected(self):
        e=replace(self.effect,revocation_epoch=4)
        with self.assertRaises(Denied): self.sink.issue_challenge(e,self.bundle,CHANNEL,NOW)
    def test_user_intent_false_denied(self):
        act=replace(self.act,nonce=b'I'*24,act_id='intent-false')
        with self.assertRaisesRegex(Denied,'user_intent_not_verified'): self.validator.prepare(act,False,NOW)
    def test_empty_session_rejected(self):
        with self.assertRaisesRegex(Denied,'invalid_session_id'): replace(self.act,session_id='').encode()
    def test_empty_act_id_rejected(self):
        with self.assertRaisesRegex(Denied,'invalid_act_id'): replace(self.act,act_id='').encode()
    def test_concurrent_same_capability_one_commit(self):
        ch1=self.challenge(); ch2=self.challenge(); pop1=self.presentation(ch1); pop2=self.presentation(ch2)
        state2=ProtectedState(self.tmp.name)
        sink2=FinalitySink(self.sink.sink_id,self.sink.boundary,self.sink.validator_keys,self.sink.requester_keys,state2,self.policy)
        barrier=threading.Barrier(2); results=[]
        def run(s,ch,pop):
            barrier.wait()
            try:results.append(s.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW))
            except Exception as exc:results.append(type(exc).__name__+':'+str(exc))
        t1=threading.Thread(target=run,args=(self.sink,ch1,pop1)); t2=threading.Thread(target=run,args=(sink2,ch2,pop2)); t1.start(); t2.start(); t1.join(); t2.join(); state2.db.close()
        self.assertEqual(sum(x=='EFFECT_COMMITTED' for x in results),1); self.assertEqual(self.state.effect_count(),1)
    def test_duplicate_act_id_with_new_nonce_rejected_at_issuance(self):
        act2=replace(self.act,nonce=b'D'*24,act_id=self.act.act_id)
        with self.assertRaisesRegex(Denied,'nonce_or_act_reuse'): self.validator.prepare(act2,True,NOW)
    def test_independent_capabilities_both_commit(self):
        self.finalize()
        act2=replace(self.act,nonce=b'2'*24,act_id='act-2'); b2=self.validator.prepare(act2,True,NOW); e2=replace(self.effect,nonce=act2.nonce,act_id=act2.act_id)
        ch2=self.sink.issue_challenge(e2,b2,CHANNEL,NOW); p2=create_presentation(b2.capability,e2,ch2,CHANNEL,self.app_key,b'assistant-key-1')
        self.assertEqual(self.sink.finalize(e2,b2,ch2,p2,CHANNEL,NOW),'EFFECT_COMMITTED'); self.assertEqual(self.state.effect_count(),2)
