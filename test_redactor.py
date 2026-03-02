import json
from processing.redactor import LogRedactor
from pprint import pprint

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

if __name__ == "__main__":
    # Test common financial logs
    test_production_redaction(profile="financial")
    
    # Test how it behaves with a medical profile (will be less aggressive on CCs, more on dates/names)
    test_production_redaction(profile="medical")
