import time
import json
import random
from typing import Dict, Any

class MockLogProducer:
    """
    Simulates a Kafka producer generating network/app logs.
    """
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.severities = ["INFO", "WARN", "ERROR", "CRITICAL"]

    def generate_log(self) -> Dict[str, Any]:
        severity = random.choice(self.severities)
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "severity": severity,
            "source": self.service_name,
            "message": self._get_random_message(severity),
            "source_ip": f"192.168.1.{random.randint(1, 255)}",
            "request_id": f"req-{random.randint(1000, 9999)}"
        }

    def _get_random_message(self, severity: str) -> str:
        messages = {
            "INFO": ["User logged in", "API request received", "Database heartbeat check"],
            "WARN": ["Slow response from auth service", "Disk usage at 85%", "Repeated login attempts"],
            "ERROR": ["Connection timeout", "Permission denied", "Upstream server unavailable"],
            "CRITICAL": ["Database connection lost", "OOM error detected", "Security breach attempt"]
        }
        return random.choice(messages[severity])

# To start a stream:
# producer = MockLogProducer("payment-service")
# while True:
#     print(json.dumps(producer.generate_log()))
#     time.sleep(1)
