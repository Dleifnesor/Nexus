from nexus.config import LLMConfig
from nexus.engine.recovery import Recovery
from nexus.llm.provider import BaseProvider, LLMError
from nexus.storage.db import Database
from nexus.tools.registry import Registry


class ScriptedProvider(BaseProvider):
    def __init__(self, response):
        super().__init__(LLMConfig())
        self._response = response

    def generate(self, prompt, system=""):
        return self._response


class BoomProvider(BaseProvider):
    def generate(self, prompt, system=""):
        raise LLMError("llm down")


def test_recovery_retry(tmp_path):
    db = Database(tmp_path / "t.db")
    p = ScriptedProvider('{"strategy": "retry", "reason": "transient"}')
    d = Recovery(p, Registry(), db, "run").decide("nmap", "10.0.0.1", "", "boom")
    assert d.strategy == "retry"


def test_recovery_alternative(tmp_path):
    db = Database(tmp_path / "t.db")
    p = ScriptedProvider('{"strategy": "alternative_tool", "alternative_tool": "nikto", "reason": "switch"}')
    d = Recovery(p, Registry(), db, "run").decide("nmap", "10.0.0.1", "", "boom")
    assert d.strategy == "alternative_tool"
    assert d.alternative_tool == "nikto"


def test_recovery_invalid_alternative_skips(tmp_path):
    db = Database(tmp_path / "t.db")
    p = ScriptedProvider('{"strategy": "alternative_tool", "alternative_tool": "doesnotexist", "reason": "x"}')
    d = Recovery(p, Registry(), db, "run").decide("nmap", "10.0.0.1", "", "boom")
    assert d.strategy == "skip"


def test_recovery_llm_failure_skips(tmp_path):
    db = Database(tmp_path / "t.db")
    d = Recovery(BoomProvider(LLMConfig()), Registry(), db, "run").decide("nmap", "10.0.0.1", "", "boom")
    assert d.strategy == "skip"


def test_record_gap(tmp_path):
    db = Database(tmp_path / "t.db")
    rid = db.create_run("scope", {}, {}, {})
    Recovery(ScriptedProvider("{}"), Registry(), db, rid).record_gap("nmap", "10.0.0.1", "failed", "skip")
    assert len(db.list_coverage_gaps(rid)) == 1
