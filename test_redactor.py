import json
from types import SimpleNamespace

import pytest

from processing.learned_pii import LearnedEntities
from processing.pii_rules import PiiRuleStore
from processing.redactor import LogRedactor


@pytest.fixture(autouse=True)
def _isolated_learned_db(monkeypatch, tmp_path):
    monkeypatch.setenv("PII_LEARNED_DB", str(tmp_path / "learned.sqlite3"))


def test_production_redaction(profile="financial"):
    print(f"\n--- TESTING WITH PROFILE: {profile} ---")
    redactor = LogRedactor(profile=profile)
    
    with open("test_data.json", "r") as f:
        logs = json.load(f)
        
    for i, log in enumerate(logs):
        print(f"\n[{i+1}] TEST CASE: {log.get('type')}")
        clean_log = redactor.redact_log(log)
        
        print(f"{'BEFORE:':<10} {log.get('message')}")
        print(f"{'AFTER:':<10} {clean_log.get('message')}")
        print("-" * 60)


def test_redactor_pii_metadata():
    redactor = LogRedactor(profile="financial")
    payload = {
        "timestamp": "2026-08-02T12:00:00Z",
        "severity": "ERROR",
        "source": "payment-service",
        "message": "User john.doe@example.com attempted a payment with card 4111 1111 1111 1111.",
        "customer_id": "8827361",
        "source_ip": "203.0.113.10",
        "request_id": "req-test-0002"
    }

    clean = redactor.redact_log(payload)
    # Sensitive IDs are pseudonymized (stable keyed hash), not blanked, so logs
    # can still be grouped by user without exposing the raw value.
    assert clean.get("customer_id", "").startswith("anon_")
    assert "8827361" not in clean["customer_id"]
    assert clean["customer_id"] == redactor.redact_log(payload)["customer_id"]
    assert clean.get("contains_pii") is True
    assert "customer_id" in clean.get("pii_fields", [])
    assert "message" in clean.get("pii_fields", [])
    assert "john.doe@example.com" not in clean["message"]


def test_ner_results_are_cached_for_identical_text():
    redactor = LogRedactor(profile="financial")
    if not redactor.ner_available:
        return  # rules-only environment: nothing to cache

    calls = []
    real = redactor.analyzer.analyze

    def counting(**kwargs):
        calls.append(kwargs["text"])
        return real(**kwargs)

    redactor.analyzer.analyze = counting
    text = "Payment declined for customer Maria Gonzalez in Madrid"
    first = redactor.redact_text(text)
    second = redactor.redact_text(text)
    assert first == second
    assert len(calls) == 1


def test_ner_cache_can_be_disabled(monkeypatch):
    monkeypatch.setenv("NER_CACHE_SIZE", "0")
    redactor = LogRedactor(profile="financial")
    redactor._ner_cache_put("x", "y", True)
    assert redactor._ner_cache_get("x") is None


def _hit(text, span, entity="PERSON"):
    start = text.index(span)
    return SimpleNamespace(entity_type=entity, start=start, end=start + len(span))


def test_learned_entities_become_rules_after_min_hits_without_storing_raw_text(tmp_path):
    db = str(tmp_path / "learned.sqlite3")
    learned = LearnedEntities(db, b"k", entities=["PERSON"], min_hits=2,
                              reload_seconds=0, allow_list=["Cisco"])
    t1 = "refund for Maria Gonzalez approved"
    learned.observe(t1, [_hit(t1, "Maria Gonzalez"), _hit(t1, "approved", "DATE_TIME")])
    assert learned.apply("call Maria Gonzalez") == ("call Maria Gonzalez", False)

    t2 = "Maria Gonzalez called again"
    learned.observe(t2, [_hit(t2, "Maria Gonzalez")])
    assert learned.apply("ticket for MARIA gonzalez, card ok") == ("ticket for [REDACTED], card ok", True)
    assert learned.apply("Maria alone is not a match") == ("Maria alone is not a match", False)

    learned.observe("Cisco Cisco", [_hit("Cisco Cisco", "Cisco")] * 2)   # allow-listed: never learned
    assert learned.size() == 1
    raw = open(db, "rb").read()
    assert b"maria" not in raw.lower() and b"gonzalez" not in raw.lower()

    reader = LearnedEntities(db, b"k", min_hits=2, reload_seconds=0, read_only=True)
    assert reader.apply("from Maria Gonzalez")[0] == "from [REDACTED]"
    assert LearnedEntities(db, b"other-key", min_hits=2, read_only=True).apply("Maria Gonzalez")[1] is False


def test_rules_only_redactor_applies_learned_entities(monkeypatch, tmp_path):
    monkeypatch.setenv("PII_LEARNED_RELOAD_SECONDS", "0")
    monkeypatch.setenv("PII_PSEUDONYM_KEY", "test-key")
    teacher = LearnedEntities.from_env(b"test-key")
    text = "Maria Gonzalez"
    teacher.observe(text, [_hit(text, text)])
    teacher.observe(text, [_hit(text, text)])

    redactor = LogRedactor(profile="financial", use_ner=False)
    assert not redactor.ner_available
    clean = redactor.redact_log({"message": "chargeback by Maria Gonzalez"})
    assert clean["message"] == "chargeback by [REDACTED]"
    assert clean["contains_pii"] is True and clean["redaction_mode"] == "rules-only"


_NAMES = ["Maria Gonzalez", "John Smith", "Ana Li", "Bob Stone", "Ana Li"]


def _observe_names(store, names=_NAMES):
    for i, name in enumerate(names):
        text = f"profile update failed for {name}, order 12{i}34 from 10.0.0.{i}"
        store.observe(text, [_hit(text, name)])


def test_pii_rule_suggestion_needs_distinct_values_and_stores_no_raw_text(tmp_path):
    db = str(tmp_path / "learned.sqlite3")
    store = PiiRuleStore(db, b"k", entities=["PERSON"], min_distinct=4, reload_seconds=0)
    _observe_names(store, _NAMES[:3])
    assert store.counts()["collecting"] == 1 and store.list("pending") == []

    _observe_names(store, _NAMES[3:])
    [rule] = store.list("pending")
    assert rule["hits"] == 5 and rule["distinct_values"] == 4 and rule["entity"] == "PERSON"
    assert rule["display"] == "profile update failed for {PERSON}, order <n> from <ip>"
    raw = open(db, "rb").read().lower()
    assert b"gonzalez" not in raw and b"smith" not in raw and b"stone" not in raw

    # Not recorded: entity type not learned, too many slots, or text too long.
    t = "login from Madrid failed"
    store.observe(t, [_hit(t, "Madrid", "LOCATION")])
    store.observe("x " * 300, [_hit("x " * 300, "x")])
    assert sum(store.counts().values()) == 1


def test_approved_pii_rule_applies_in_rules_only_readers(monkeypatch, tmp_path):
    monkeypatch.setenv("PII_LEARNED_RELOAD_SECONDS", "0")
    monkeypatch.setenv("PII_PSEUDONYM_KEY", "test-key")
    monkeypatch.setenv("PII_SUGGEST_MIN_DISTINCT", "3")
    teacher = PiiRuleStore.from_env(b"test-key")
    _observe_names(teacher)
    rid = teacher.list("pending")[0]["id"]

    text = "Profile update failed for Zed Quux, order 999 from 10.1.2.3"
    redactor = LogRedactor(profile="financial", use_ner=False)
    assert redactor.redact_log({"message": text})["message"] == text

    assert teacher.decide([rid], "approved", by="tester")[0]["decided_by"] == "tester"
    assert redactor.redact_log({"message": text})["message"] == (
        "Profile update failed for [REDACTED], order 999 from 10.1.2.3")
    assert redactor.rules.apply("unrelated text for Zed Quux") == ("unrelated text for Zed Quux", False)

    teacher.decide([rid], "rejected", by="tester")
    assert redactor.redact_log({"message": text})["message"] == text
    with pytest.raises(ValueError):
        teacher.decide([rid], "collecting", by="tester")


if __name__ == "__main__":
    # Test common financial logs
    test_production_redaction(profile="financial")
    
    # Test how it behaves with a medical profile (will be less aggressive on CCs, more on dates/names)
    test_production_redaction(profile="medical")
