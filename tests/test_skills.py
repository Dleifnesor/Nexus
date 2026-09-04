"""Tests for the skills system and prompt intake."""
from nexus.intake.brief import _clean, parse_brief
from nexus.llm.schema import EngagementBrief
from nexus.skills.select import relevant, render
from nexus.skills.store import Skill, SkillStore, _normalize_name, _parse_skill
from nexus.skills.writer import SkillWriter
from nexus.storage.db import Database


# -- store: builtin seeds load, learned skills persist ----------------------
def test_store_loads_builtin_seeds(tmp_path):
    store = SkillStore(tmp_path / "skills")  # empty user dir
    names = {s.name for s in store.all()}
    assert {"wordpress-enum", "smb-ad-enum", "tls-audit"} <= names
    wp = store.get("wordpress-enum")
    assert wp.source == "builtin" and "wpscan" in wp.triggers


def test_store_upsert_writes_and_reloads(tmp_path):
    user = tmp_path / "skills"
    store = SkillStore(user)
    stored = store.upsert(Skill(name="My New Skill!", description="d", triggers=["x"], body="do x"))
    assert stored is not None and stored.name == "my-new-skill"
    assert (user / "my-new-skill.md").exists()
    # a fresh store reads it back from disk
    assert SkillStore(user).get("my-new-skill").body == "do x"


def test_store_rejects_bad_name(tmp_path):
    assert SkillStore(tmp_path / "s").upsert(Skill(name="!!!", body="x")) is None


def test_normalize_name():
    assert _normalize_name("WordPress Enum") == "wordpress-enum"
    assert _normalize_name("  a_b/c  ") == "a-b-c"
    assert _normalize_name("###") == ""


def test_parse_skill_roundtrip(tmp_path):
    md = (
        "---\nname: demo\ndescription: a demo\ntriggers: [foo, bar]\nsource: builtin\n---\n\nbody text\n"
    )
    skill = _parse_skill(md, tmp_path / "demo.md", "learned")
    assert skill.name == "demo"
    assert skill.triggers == ["foo", "bar"]
    assert skill.body == "body text"
    assert skill.source == "builtin"


# -- select: trigger and focus matching -------------------------------------
def test_relevant_matches_triggers_and_focus():
    skills = [
        Skill(name="wordpress-enum", triggers=["wordpress", "wpscan"], body="b1"),
        Skill(name="tls-audit", triggers=["tls", "ssl"], body="b2"),
    ]
    context = "Services: 10.0.0.1:80 wordpress detected"
    chosen = relevant(skills, context)
    assert chosen and chosen[0].name == "wordpress-enum"

    chosen_focus = relevant(skills, "nothing here", focus=["tls-audit"])
    assert chosen_focus and chosen_focus[0].name == "tls-audit"


def test_render_labels_as_reference():
    out = render([Skill(name="x", description="d", body="steps")])
    assert "reference only" in out and "x: d" in out and "steps" in out


# -- intake: prompt -> brief -------------------------------------------------
class _FakeProvider:
    def __init__(self, brief):
        self.brief = brief

    def generate_structured(self, prompt, model, system=""):
        return self.brief


def test_parse_brief_cleans_and_dedupes():
    raw = EngagementBrief(
        scope=[" 10.0.0.0/24 ", "10.0.0.0/24", "acme.local"],
        exclusions=["10.0.0.5"],
        objective="  find auth bypass  ",
        focus=["Web-Auth", "web-auth"],
    )
    brief = parse_brief(_FakeProvider(raw), "assess acme.local")
    assert brief.scope == ["10.0.0.0/24", "acme.local"]
    assert brief.objective == "find auth bypass"
    assert brief.focus == ["web-auth"]


def test_parse_brief_empty_prompt_returns_empty():
    assert parse_brief(_FakeProvider(None), "   ").scope == []


def test_clean_helper():
    assert _clean([" a ", "a", "", "b"]) == ["a", "b"]


# -- writer: distill upserts a learned skill --------------------------------
class _DraftProvider:
    def generate_structured(self, prompt, model, system=""):
        return model(name="learned-x", description="d", triggers=["t"], body="use tool y then z")


def test_skill_writer_learns_from_findings(tmp_path):
    db = Database(tmp_path / "t.db")
    rid = db.create_run("scope", {}, {}, {})
    db.add_finding(rid, "SQLi on host", severity="high", source_tool="sqlmap")
    store = SkillStore(tmp_path / "skills")
    skill = SkillWriter(_DraftProvider(), db, rid, store).learn(objective="find sqli")
    assert skill is not None and skill.name == "learned-x"
    assert SkillStore(tmp_path / "skills").get("learned-x") is not None
    db.close()


def test_skill_writer_no_findings_no_skill(tmp_path):
    db = Database(tmp_path / "t.db")
    rid = db.create_run("scope", {}, {}, {})
    store = SkillStore(tmp_path / "skills")
    assert SkillWriter(_DraftProvider(), db, rid, store).learn() is None
    db.close()
