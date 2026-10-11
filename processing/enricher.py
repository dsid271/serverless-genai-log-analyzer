import ipaddress
import os
from typing import Dict, List, Any, Optional, Any as AnyType


def classify_ip(value: Any) -> Optional[str]:
    """Network scope of an IP address, derived from the address itself."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved or ip.is_unspecified or ip.is_link_local:
        return "reserved"
    return "public"


class LogEnricher:
    """
    Redacts a log entry, then adds fields computed from the entry itself and,
    when `ip_intel` is configured, country and reputation for public IPs.
    """
    def __init__(self, redactor: Optional[AnyType] = None, ip_intel: Optional[AnyType] = None):
        if redactor is None:
            from processing.redactor import LogRedactor
            redactor = LogRedactor()
        self.redactor = redactor
        self.ip_intel = ip_intel
        self.ip_fields = [f.strip() for f in os.getenv("IP_ENRICH_FIELDS", "source_ip").split(",") if f.strip()]

    def _public_ips(self, log_entry: Dict[str, Any]) -> Dict[str, str]:
        out = {}
        for field in self.ip_fields:
            value = log_entry.get(field)
            if value is not None and classify_ip(value) == "public":
                out[field] = str(value).strip()
        return out

    def process_log(
        self, log_entry: Dict[str, Any], intel: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Main processing pipeline: Redact -> Enrich -> Return.
        """
        # Classify and look up before redaction may rewrite the address.
        ip_scope = classify_ip(log_entry["source_ip"]) if "source_ip" in log_entry else None
        public = self._public_ips(log_entry) if self.ip_intel is not None else {}
        lookups = {
            field: (intel[ip] if intel is not None and ip in intel else self.ip_intel.lookup(ip))
            for field, ip in public.items()
        }

        processed_log = self.redactor.redact_log(log_entry)

        if ip_scope is not None:
            processed_log["source_ip_scope"] = ip_scope
        for field, result in lookups.items():
            for key, value in result.items():
                processed_log[f"{field}_{key}"] = value

        return processed_log

    def process_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch version: each distinct public IP is looked up once, concurrently."""
        intel = None
        if self.ip_intel is not None:
            intel = self.ip_intel.lookup_many(ip for log in logs for ip in self._public_ips(log).values())
        return [self.process_log(log, intel) for log in logs]
