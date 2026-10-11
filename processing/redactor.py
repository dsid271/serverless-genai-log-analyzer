import hashlib
import hmac
import logging
import os
import re
import threading
from collections import OrderedDict
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

import yaml

from processing.learned_pii import DEFAULT_PSEUDONYM_KEY, LearnedEntities
from processing.pii_rules import PiiRuleStore

logger = logging.getLogger(__name__)

# --- Tier 1: deterministic rules (always on, cannot fail) --------------------

SENSITIVE_KEYS = {
    "customer_id", "user_id", "userid", "phone", "phone_number", "email",
    "client_ip", "ip", "password", "passwd", "secret", "token", "api_key",
    "authorization", "ssn", "account_number", "card_number", "cvv",
}

CARD_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _luhn_valid(digits: str) -> bool:
    """Rejects timestamps and order IDs that merely look like card numbers."""
    if not 13 <= len(digits) <= 19:
        return False
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _mask_card(match: re.Match) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    if not _luhn_valid(digits):
        return match.group(0)          # false positive — leave it alone
    return f"{'*' * (len(digits) - 4)}{digits[-4:]}"


def _mask_email(match: re.Match) -> str:
    local, _, domain = match.group(0).partition("@")
    head = local[0] if local else "*"
    return f"{head}{'*' * max(len(local) - 1, 1)}@{domain}"


class RuleRedactor:
    """Fast, deterministic, zero-dependency. The floor that always applies.

    `learned` (processing/learned_pii.py) adds entities that NER found earlier.
    `pii_rules` (processing/pii_rules.py) adds approved per-pattern slot rules."""

    def __init__(self, learned: Optional[Any] = None, pii_rules: Optional[Any] = None):
        self.learned = learned
        self.pii_rules = pii_rules

    def apply(self, text: str) -> Tuple[str, bool]:
        original = text
        text = CARD_RE.sub(_mask_card, text)
        text = SSN_RE.sub("***-**-****", text)
        text = EMAIL_RE.sub(_mask_email, text)
        if self.learned is not None:
            text, _ = self.learned.apply(text)
        if self.pii_rules is not None:
            text, _ = self.pii_rules.apply(text)
        return text, text != original


# --- Tier 2: Presidio NER (optional, for free text) -------------------------

class _EngineCache:
    """Caches the expensive spaCy model separately from per-profile analyzers."""

    _lock = threading.Lock()
    _nlp_engines: Dict[str, Any] = {}
    _analyzers: Dict[Tuple[str, str], Any] = {}
    _anonymizer = None

    @classmethod
    def get(cls, profile: str, model_name: str, config: dict):
        from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_anonymizer import AnonymizerEngine

        key = (profile, model_name)
        with cls._lock:
            if key in cls._analyzers:
                return cls._analyzers[key], cls._anonymizer

            if model_name not in cls._nlp_engines:
                provider = NlpEngineProvider(nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": model_name}],
                })
                cls._nlp_engines[model_name] = provider.create_engine()

            analyzer = AnalyzerEngine(nlp_engine=cls._nlp_engines[model_name])
            for c in config.get("custom_recognizers", []):
                analyzer.registry.add_recognizer(PatternRecognizer(
                    supported_entity=c["entity"],
                    patterns=[Pattern(name=c["name"], regex=c["regex"],
                                      score=c["score"])],
                ))

            if cls._anonymizer is None:
                cls._anonymizer = AnonymizerEngine()

            cls._analyzers[key] = analyzer
            return analyzer, cls._anonymizer


# --- Orchestrator ----------------------------------------------------------

class LogRedactor:
    FREE_TEXT_FIELDS = {"message", "error_details", "description",
                        "stack_trace", "raw", "body", "query"}

    def __init__(self, profile: str = "financial", model_size: str = "sm",
                 pseudonym_key: Optional[bytes] = None, use_ner: bool = True):
        self.profile = profile
        self.rules = RuleRedactor()
        self.analyzer = None
        self.anonymizer = None
        self.ner_available = False
        # Exact-text cache of NER results (0 disables it).
        self._ner_cache_size = int(os.getenv("NER_CACHE_SIZE", "4096"))
        self._ner_cache: "OrderedDict[str, Tuple[str, bool]]" = OrderedDict()
        self._ner_cache_lock = threading.Lock()
        self._key = pseudonym_key or os.environ.get(
            "PII_PSEUDONYM_KEY", DEFAULT_PSEUDONYM_KEY).encode()

        self.config = self._load_config(profile)
        self.entities = self.config.get("entities")
        self.score_threshold = self.config.get("score_threshold", 0.4)
        self.operators: dict = {}
        self.allow_list = self.config.get("allow_list", [])
        self.ip_allow = tuple(self.config.get("ip_allow_prefixes", []))
        # Without NER nothing new is learned; the store is only read.
        # Raises if PII_LEARNING is on while the key is the public default.
        self.learned = LearnedEntities.from_env(self._key, self.allow_list, read_only=not use_ner)
        self.pii_rules = PiiRuleStore.from_env(self._key, read_only=not use_ner)
        if self._key == DEFAULT_PSEUDONYM_KEY.encode():
            logger.warning("PII_PSEUDONYM_KEY is the public default %r: pseudonyms and the hashes in the "
                           "PII rule store are guessable. Set a secret key before using real data.",
                           DEFAULT_PSEUDONYM_KEY)
        self.rules = RuleRedactor(self.learned, self.pii_rules)
        if not use_ner:
            logger.info("NER disabled by caller; rules-only mode (learned entities: %s, pii rules: %s).",
                        "on" if self.learned is not None else "off",
                        "on" if self.pii_rules is not None else "off")
            return
        try:
            self.operators = self._build_operators(self.config)
            model = self.config.get("nlp_model", f"en_core_web_{model_size}")
            self.analyzer, self.anonymizer = _EngineCache.get(profile, model, self.config)
            self.ner_available = True
        except (Exception, SystemExit) as e:
            # Degrade to rules only — never degrade to no redaction.
            # SystemExit is caught explicitly: presidio's SpacyNlpEngine.load()
            # auto-downloads the spaCy model via spacy.cli.download(), which
            # calls sys.exit(1) on a failed download (e.g. no network, no pip
            # in the venv, or a blocked GitHub release URL). Without catching
            # it here, that SystemExit would propagate past this handler and
            # crash the caller instead of degrading to rule-only redaction.
            logger.error("Presidio unavailable (%s). Rule-only mode active. "
                         "Named-entity PII will NOT be caught.", e)

    def _build_operators(self, cfg: dict) -> dict:
        from presidio_anonymizer.entities import OperatorConfig

        ops = {}
        for entity, spec in (cfg.get("operators") or {}).items():
            spec = dict(spec)
            ops[entity] = OperatorConfig(spec.pop("type", "replace"), spec)
        ops.setdefault("DEFAULT", OperatorConfig("replace", {"new_value": "[REDACTED]"}))
        return ops
        
    def _load_config(self, profile: str) -> dict:
        path = os.path.join(os.path.dirname(__file__), "pii_profiles.yaml")
        try:
            with open(path) as f:
                doc = yaml.safe_load(f)
            profiles = doc.get("profiles", {})
            self.ruleset_version = doc.get("version", "unknown")
        except Exception as e:
            logger.error("Cannot read %s (%s); rule-only mode.", path, e)
            self.ruleset_version = "none"
            return {}

        if profile in profiles:
            return profiles[profile]

        # Fall back to the superset profile, not to `general`.
        logger.warning("Profile %r not found; falling back to 'strict'.", profile)
        return profiles.get("strict", {})

    def _pseudonymize(self, value: Any) -> str:
        """Stable token: same user always maps to the same ID, no PII exposed.
        Lets you still group logs by user without storing the identifier."""
        digest = hmac.new(self._key, str(value).encode(), hashlib.sha256)
        return f"anon_{digest.hexdigest()[:16]}"

    def _is_internal_ip(self, text: str, result) -> bool:
        """Keep RFC1918 addresses — not personal data, and needed for triage."""
        if result.entity_type != "IP_ADDRESS" or not self.ip_allow:
            return False
        return text[result.start:result.end].startswith(self.ip_allow)

    def redact_text(self, text: str) -> Tuple[str, bool]:
        text, changed = self.rules.apply(text)          # rules first, always
        if not self.ner_available or not text:
            return text, changed

        # Identical messages are common; the NER result depends only on the text,
        # so a repeat is answered from the cache with no loss of coverage.
        cached = self._ner_cache_get(text)
        if cached is not None:
            return cached[0], changed or cached[1]

        source = text
        try:
            results = self.analyzer.analyze(
                text=text,
                entities=self.entities,
                language="en",
                score_threshold=self.score_threshold,
                allow_list=self.allow_list,
            )
            results = [r for r in results if not self._is_internal_ip(text, r)]
            if self.learned is not None:
                self.learned.observe(text, results)
            if self.pii_rules is not None:
                self.pii_rules.observe(text, results)
            ner_changed = False
            if results:
                text = self.anonymizer.anonymize(
                    text=text, analyzer_results=results, operators=self.operators
                ).text
                ner_changed = True
            self._ner_cache_put(source, text, ner_changed)   # failures are not cached
            changed = changed or ner_changed
        except Exception as e:
            logger.error("NER pass failed, rules already applied: %s", e)
        return text, changed

    def _ner_cache_get(self, key: str) -> Optional[Tuple[str, bool]]:
        if self._ner_cache_size <= 0:
            return None
        with self._ner_cache_lock:
            hit = self._ner_cache.get(key)
            if hit is not None:
                self._ner_cache.move_to_end(key)
            return hit

    def _ner_cache_put(self, key: str, text: str, ner_changed: bool) -> None:
        if self._ner_cache_size <= 0:
            return
        with self._ner_cache_lock:
            self._ner_cache[key] = (text, ner_changed)
            self._ner_cache.move_to_end(key)
            while len(self._ner_cache) > self._ner_cache_size:
                self._ner_cache.popitem(last=False)

    def _walk(self, node: Any, path: str, hits: List[str]) -> Any:
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                child = f"{path}.{k}" if path else k
                if k.lower() in SENSITIVE_KEYS:
                    out[k] = self._pseudonymize(v) if "id" in k.lower() else "[REDACTED]"
                    hits.append(child)
                else:
                    out[k] = self._walk(v, child, hits)
            return out

        if isinstance(node, list):
            return [self._walk(v, f"{path}[{i}]", hits)
                    for i, v in enumerate(node)]

        if isinstance(node, str):
            leaf = path.rsplit(".", 1)[-1].split("[")[0]
            # Run full NER only on likely prose; rules on everything else.
            if leaf in self.FREE_TEXT_FIELDS or len(node) > 40:
                cleaned, changed = self.redact_text(node)
            else:
                cleaned, changed = self.rules.apply(node)
            if changed:
                hits.append(path)
            return cleaned

        return node

    def redact_log(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        hits: List[str] = []
        clean = self._walk(deepcopy(log_entry), "", hits)
        clean["pii_fields"] = sorted(set(hits))
        clean["contains_pii"] = bool(hits)
        clean["redaction_mode"] = "rules+ner" if self.ner_available else "rules-only"
        clean["redaction_profile"] = f"{self.profile}@v{self.ruleset_version}"
        return clean