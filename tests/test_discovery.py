from nexus.config import LLMConfig, Mode
from nexus.llm.provider import BaseProvider
from nexus.tools.discovery import ToolDiscovery
from nexus.tools.registry import Registry


class ScriptedProvider(BaseProvider):
    def __init__(self, response):
        super().__init__(LLMConfig())
        self._response = response

    def generate(self, prompt, system=""):
        return self._response


def test_no_search_backend():
    r = Registry()
    d = ToolDiscovery(r, ScriptedProvider("{}"), Mode.SANDBOX, search_fn=None)
    assert d.discover("web dir brute") is None


def test_discover_registers_tool():
    r = Registry()
    resp = (
        '{"name": "gobuster", "category": "web", "when_to_use": "dir brute", '
        '"install": "apt-get install -y gobuster", "image": null, '
        '"cmd_template": ["gobuster", "dir", "-u", "{target}"], "parser": "generic"}'
    )
    d = ToolDiscovery(r, ScriptedProvider(resp), Mode.SANDBOX, search_fn=lambda q: "results")
    entry = d.discover("web dir brute")
    assert entry is not None
    assert entry.name == "gobuster"
    assert entry.builtin is False
    assert r.get("gobuster") is entry


def test_discover_discards_empty_template():
    r = Registry()
    resp = (
        '{"name": "x", "category": "recon", "when_to_use": "y", "install": "", '
        '"image": null, "cmd_template": [], "parser": "generic"}'
    )
    d = ToolDiscovery(r, ScriptedProvider(resp), Mode.SANDBOX, search_fn=lambda q: "results")
    assert d.discover("x") is None
    assert r.get("x") is None


def test_discover_search_failure():
    r = Registry()

    def boom(q):
        raise RuntimeError("network")

    d = ToolDiscovery(r, ScriptedProvider("{}"), Mode.SANDBOX, search_fn=boom)
    assert d.discover("x") is None
