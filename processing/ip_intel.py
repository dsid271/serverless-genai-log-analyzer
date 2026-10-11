"""
IP enrichment: country from a local MaxMind GeoLite2 database and reputation
from the AbuseIPDB API. Both are optional and configured from the environment:

- GEOIP_DB_PATH: path to GeoLite2-Country.mmdb or GeoLite2-City.mmdb
- ABUSEIPDB_API_KEY: AbuseIPDB key (free tier: 1,000 checks/day)

Only public addresses are looked up. Results are cached in memory, and
AbuseIPDB calls stop for the day once ABUSEIPDB_DAILY_LIMIT is reached.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Iterable, Optional, Tuple

logger = logging.getLogger(__name__)

_ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"


class IpIntel:
    def __init__(
        self,
        geo_db_path: Optional[str] = None,
        abuse_api_key: Optional[str] = None,
        *,
        malicious_score: int = 50,
        cache_seconds: int = 86400,
        daily_limit: int = 900,
        timeout: float = 5.0,
    ) -> None:
        self._geo = None
        self._geo_city = False
        if geo_db_path:
            import geoip2.database

            self._geo = geoip2.database.Reader(geo_db_path)
            self._geo_city = "City" in self._geo.metadata().database_type
        self._abuse_key = abuse_api_key
        self.malicious_score = malicious_score
        self._cache_seconds = cache_seconds
        self._daily_limit = daily_limit
        self._timeout = timeout
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._day = ""
        self._calls_today = 0

    @classmethod
    def from_env(cls) -> Optional["IpIntel"]:
        geo = os.getenv("GEOIP_DB_PATH") or None
        key = os.getenv("ABUSEIPDB_API_KEY") or None
        if geo and not os.path.exists(geo):
            logger.warning("GEOIP_DB_PATH=%s does not exist; GeoIP lookups disabled", geo)
            geo = None
        if not geo and not key:
            return None
        return cls(
            geo,
            key,
            malicious_score=int(os.getenv("ABUSEIPDB_MALICIOUS_SCORE", "50")),
            cache_seconds=int(os.getenv("IP_INTEL_CACHE_SECONDS", "86400")),
            daily_limit=int(os.getenv("ABUSEIPDB_DAILY_LIMIT", "900")),
        )

    def status(self) -> Dict[str, Any]:
        return {
            "geoip": self._geo is not None,
            "abuseipdb": bool(self._abuse_key),
            "abuseipdb_calls_today": self._calls_today,
            "abuseipdb_daily_limit": self._daily_limit,
            "cached_ips": len(self._cache),
        }

    def lookup(self, ip: str) -> Dict[str, Any]:
        """Flat, scalar-only result so it can be stored in Delta Lake and Chroma."""
        now = time.time()
        with self._lock:
            hit = self._cache.get(ip)
            if hit and now - hit[0] < self._cache_seconds:
                return hit[1]
        result: Dict[str, Any] = {}
        country = self._country(ip)
        if country:
            result["country"] = country
        abuse = self._abuse(ip)
        if abuse is not None:
            result.update(abuse)
        elif self._abuse_key:
            # Failed or over budget: do not cache, so a later batch can retry.
            return result
        with self._lock:
            self._cache[ip] = (now, result)
        return result

    def lookup_many(self, ips: Iterable[str], workers: int = 8) -> Dict[str, Dict[str, Any]]:
        unique = sorted(set(ips))
        if not unique:
            return {}
        with ThreadPoolExecutor(max_workers=min(workers, len(unique))) as pool:
            return dict(zip(unique, pool.map(self.lookup, unique)))

    def _country(self, ip: str) -> Optional[str]:
        if self._geo is None:
            return None
        try:
            rec = self._geo.city(ip) if self._geo_city else self._geo.country(ip)
        except Exception:
            # AddressNotFoundError for unallocated ranges; nothing to add.
            return None
        return rec.country.iso_code

    def _take_budget(self) -> bool:
        with self._lock:
            today = time.strftime("%Y-%m-%d", time.gmtime())
            if today != self._day:
                self._day, self._calls_today = today, 0
            if self._calls_today >= self._daily_limit:
                return False
            self._calls_today += 1
            return True

    def _abuse(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self._abuse_key or not self._take_budget():
            return None
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        req = urllib.request.Request(
            f"{_ABUSE_URL}?{query}", headers={"Key": self._abuse_key, "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode("utf-8")).get("data") or {}
        except urllib.error.HTTPError as e:
            if e.code == 429:
                with self._lock:
                    self._calls_today = self._daily_limit
            logger.warning("AbuseIPDB lookup failed: HTTP %s", e.code)
            return None
        except Exception as e:
            logger.warning("AbuseIPDB lookup failed: %s", e)
            return None
        score = int(data.get("abuseConfidenceScore") or 0)
        return {
            "abuse_score": score,
            "abuse_reports": int(data.get("totalReports") or 0),
            "malicious": score >= self.malicious_score,
        }
