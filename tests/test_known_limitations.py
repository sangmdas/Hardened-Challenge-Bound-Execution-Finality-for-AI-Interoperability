"""Known deployment limitations. These are intentionally not counted as security wins."""
from __future__ import annotations
import os, shutil, sqlite3, tempfile
from common import Harness,NOW,CHANNEL
from interoperability_hardened.core import FinalitySink,ProtectedState

class KnownLimitations(Harness):
    def test_limitation_plain_sqlite_snapshot_rollback_can_restore_consumability(self):
        snap=tempfile.NamedTemporaryFile(delete=False); snap.close(); dest=sqlite3.connect(snap.name); self.state.db.backup(dest); dest.close()
        self.finalize(); self.state.db.close()
        for suffix in ('-wal','-shm'):
            try:os.unlink(self.tmp.name+suffix)
            except OSError:pass
        shutil.copyfile(snap.name,self.tmp.name); os.unlink(snap.name)
        self.state=ProtectedState(self.tmp.name)
        sink=FinalitySink(self.sink.sink_id,self.sink.boundary,self.sink.validator_keys,self.sink.requester_keys,self.state,self.policy)
        ch=sink.issue_challenge(self.effect,self.bundle,CHANNEL,NOW)
        pop=self.presentation(ch)
        self.assertEqual(sink.finalize(self.effect,self.bundle,ch,pop,CHANNEL,NOW),'EFFECT_COMMITTED')
