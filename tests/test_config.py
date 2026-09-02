from nexus.config import Budgets, Config, LLMConfig, Mode, load_env_overrides


def test_mode_values():
    assert Mode.SCOPE.value == "scope"
    assert Mode.SANDBOX.value == "sandbox"


def test_to_dict_redacts_secrets():
    cfg = Config(
        mode=Mode.SCOPE,
        llm=LLMConfig(api_key="secret"),
        nvd_api_key="nvd-secret",
        hibp_api_key="hibp-secret",
    )
    d = cfg.to_dict()
    assert d["llm"]["api_key"] is True
    assert "nvd_api_key" not in d
    assert "hibp_api_key" not in d


def test_to_dict_serializes_mode_and_paths():
    cfg = Config(mode=Mode.SCOPE)
    d = cfg.to_dict()
    assert d["mode"] == "scope"
    assert d["out_dir"] == str(cfg.out_dir)
    assert d["data_dir"] == str(cfg.data_dir)


def test_load_env_overrides(monkeypatch):
    cfg = Config(mode=Mode.SCOPE, llm=LLMConfig(provider="ollama"))
    monkeypatch.setenv("NEXUS_LLM_API_KEY", "k")
    monkeypatch.setenv("NEXUS_NVD_API_KEY", "n")
    monkeypatch.setenv("NEXUS_HIBP_API_KEY", "h")
    cfg = load_env_overrides(cfg)
    assert cfg.llm.api_key == "k"
    assert cfg.nvd_api_key == "n"
    assert cfg.hibp_api_key == "h"
    assert cfg.llm.base_url == "http://localhost:11434"


def test_load_env_overrides_preserves_explicit(monkeypatch):
    cfg = Config(mode=Mode.SCOPE, llm=LLMConfig(provider="openai", base_url="https://x", api_key="a"))
    monkeypatch.setenv("NEXUS_LLM_BASE_URL", "https://env")
    cfg = load_env_overrides(cfg)
    assert cfg.llm.base_url == "https://x"
    assert cfg.llm.api_key == "a"


def test_budgets_defaults():
    b = Budgets()
    assert b.max_time_seconds == 3600
    assert b.max_tokens == 2_000_000
    assert b.max_actions == 500
    assert b.convergence_iters == 3
