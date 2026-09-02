from nexus.config import Config, LLMConfig, Mode
from nexus.preflight import COMMON_TOOLS, check_builtin_tools, run_all


def test_check_builtin_tools():
    names = [r.name for r in check_builtin_tools()]
    assert all(f"tool:{t}" in names for t in COMMON_TOOLS)


def test_run_all_returns_expected_names():
    cfg = Config(mode=Mode.SCOPE, llm=LLMConfig(provider="openai", api_key="k"))
    names = [r.name for r in run_all(cfg)]
    assert names[0] == "docker"
    assert names[1] == "llm(openai)"
    assert names[2] == "playwright"
