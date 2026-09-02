from nexus.config import Budgets
from nexus.engine.budget import BudgetTracker
from nexus.llm.provider import TokenCounter


def test_time_exhaustion():
    t = BudgetTracker(Budgets(max_time_seconds=0), TokenCounter())
    state = t.check()
    assert state.exhausted()
    assert "time budget" in state.reason


def test_action_exhaustion():
    t = BudgetTracker(Budgets(max_actions=2), TokenCounter())
    t.record_action()
    t.record_action()
    state = t.check()
    assert state.exhausted()
    assert "action budget" in state.reason


def test_token_exhaustion():
    counter = TokenCounter()
    counter.total = 100
    t = BudgetTracker(Budgets(max_tokens=50), counter)
    state = t.check()
    assert state.exhausted()
    assert "token budget" in state.reason


def test_not_exhausted():
    t = BudgetTracker(Budgets(max_time_seconds=3600, max_actions=500, max_tokens=2_000_000), TokenCounter())
    assert not t.check().exhausted()


def test_record_and_snapshot():
    t = BudgetTracker(Budgets(max_actions=500), TokenCounter())
    t.record_action()
    snap = t.snapshot()
    assert snap["actions"] == 1
    assert {"actions", "elapsed_s", "tokens", "max_actions", "max_time_s", "max_tokens"} <= set(snap)


def test_restore_preserves_accumulated_usage():
    t = BudgetTracker(Budgets(max_actions=500, max_time_seconds=3600), TokenCounter())
    t.restore({"actions": 10, "elapsed_s": 120.0})
    assert t.actions == 10
    assert t.elapsed() >= 120.0


def test_restore_then_exhaust_action_budget():
    t = BudgetTracker(Budgets(max_actions=10), TokenCounter())
    t.restore({"actions": 9, "elapsed_s": 0.0})
    assert not t.check().exhausted()
    t.record_action()
    assert t.check().exhausted()
