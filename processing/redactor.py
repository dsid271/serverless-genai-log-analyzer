import yaml
import os
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from presidio_analyzer.nlp_engine import NlpEngineProvider
from typing import Dict, Any, List

class LogRedactor:
    _analyzer = None  # Class-level variables (Singleton pattern)
    _anonymizer = None
    _current_profile = None

    def __init__(self, profile="financial", model_size="sm"):
        # 1. Load Profile configuration from YAML
        config_path = os.path.join(os.path.dirname(__file__), "pii_profiles.yaml")
        with open(config_path, "r") as f:
            all_profiles = yaml.safe_load(f)["profiles"]
            self.config = all_profiles.get(profile, all_profiles["general"])
        
        self.entities = self.config["entities"]
        self.score_threshold = self.config.get("score_threshold", 0.4)
        self.operators = {
            "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})
        }

        # 2. Engines (Re-initialize if profile changes or first time)
        if LogRedactor._analyzer is None or LogRedactor._current_profile != profile:
            print(f"--- Loading PII Engines (Profile: {profile}, Model: {model_size}) ---")
            
            configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": f"en_core_web_{model_size}"}],
            }
            provider = NlpEngineProvider(nlp_configuration=configuration)
            nlp_engine = provider.create_engine()
            
            analyzer = AnalyzerEngine(nlp_engine=nlp_engine, default_score_threshold=self.score_threshold)

            # Add custom recognizers from the YAML profile
            for custom in self.config.get("custom_recognizers", []):
                pattern = Pattern(name=custom["name"], regex=custom["regex"], score=custom["score"])
                recognizer = PatternRecognizer(supported_entity=custom["entity"], patterns=[pattern])
                analyzer.registry.add_recognizer(recognizer)

            self.analyzer = analyzer
            self.anonymizer = AnonymizerEngine()
            
            LogRedactor._analyzer = self.analyzer
            LogRedactor._anonymizer = self.anonymizer
            LogRedactor._current_profile = profile
        else:
            self.analyzer = LogRedactor._analyzer
            self.anonymizer = LogRedactor._anonymizer


    def redact_text(self, text: str) -> str:
        """ 
        The "Intelligence": Uses Presidio to find PII in raw strings.
        """
        if not text:
            return text

        # 1. Analyze: Find the PII entities in the text
        # 'score_threshold' is for confidence. 0.4 means "if it's 40% sure it's PII, flag it"
        results = self.analyzer.analyze(
            text=text, 
            entities=self.entities, 
            language='en',
            score_threshold=0.4
        )

        # 2. Anonymize: Actually replace the found fragments
        anonymized_result = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators={"DEFAULT": self.operators["DEFAULT"]}
        )

        return anonymized_result.text

    def redact_structured_fields(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        The "Safety Net": Masks known sensitive keys in the log dictionary.
        """
        sensitive_keys = {"customer_id", "user_id", "phone", "email", "client_ip", "password"}
        
        for key in log_entry:
            # If the key itself is sensitive (like 'customer_id'), we hide its value immediately
            if key.lower() in sensitive_keys:
                log_entry[key] = "[REDACTED]"
        
        return log_entry

    def redact_log(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        The "Orchestrator": Combines structured and unstructured redaction.
        """
        # Always work on a copy to avoid side-effects
        clean_entry = log_entry.copy()
        
        # 1. First, handle fixed sensitive fields
        clean_entry = self.redact_structured_fields(clean_entry)
        
        # 2. Second, run the AI model on the 'message' or 'payload' fields
        fields_to_analyze = ["message", "error_details", "description"]
        for field in fields_to_analyze:
            if field in clean_entry and isinstance(clean_entry[field], str):
                clean_entry[field] = self.redact_text(clean_entry[field])
            
        return clean_entry
