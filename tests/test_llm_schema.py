import pytest

from nexus.llm.provider import BaseProvider, _extract_json
from nexus.llm.schema import ActionProposal


class FakeProvider(BaseProvider):
    def __init__(self, response: str):
        from nexus.config import LLMConfig

        super().__init__(LLMConfig())
        self._response = response
        self.calls = 0

    def generate(self, prompt: str, system: str = "") -> str:
        self.calls += 1
        return self._response


def test_extract_json_plain():
    assert _extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_with_fence_and_prose():
    raw = "Sure, here you go:\n```json\n{\"action_type\": \"finish_phase\"}\n```\nDone."
    assert _extract_json(raw)["action_type"] == "finish_phase"


def test_extract_json_nested():
    raw = 'noise {"a": {"b": 2}, "c": [1,2]} trailing'
    assert _extract_json(raw) == {"a": {"b": 2}, "c": [1, 2]}


def test_generate_structured_parses_action():
    p = FakeProvider('{"action_type": "run_tool", "tool": "nmap", "target": "10.0.0.1"}')
    result = p.generate_structured("x", ActionProposal)
    assert isinstance(result, ActionProposal)
    assert result.tool == "nmap"


def test_extract_json_raises_without_object():
    with pytest.raises(ValueError):
        _extract_json("no json here")
