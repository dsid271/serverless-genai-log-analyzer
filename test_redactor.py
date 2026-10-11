import json
from processing.redactor import LogRedactor

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


if __name__ == "__main__":
    # Test common financial logs
    test_production_redaction(profile="financial")
    
    # Test how it behaves with a medical profile (will be less aggressive on CCs, more on dates/names)
    test_production_redaction(profile="medical")
