"""
Ownership-based incident routing.

Reads a YAML ownership map (OWNERSHIP_FILE, default ./config/ownership.yaml):

    default_team: platform-oncall
    teams:
      payments:
        services: ["payments-*", "checkout-web"]   # fnmatch patterns
        tier: 1                                    # 1 = most critical
        oncall: payments-oncall@example.com
        channel: "#payments-incidents"

An incident goes to the team owning the source with the most errors. Other
owning teams are listed under `also_affected`. Unowned sources go to
`default_team`.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from typing import Any, Dict, Iterable, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)

UNASSIGNED = "unassigned"


class OwnershipMap:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or os.getenv("OWNERSHIP_FILE", "./config/ownership.yaml")
        self.default_team = UNASSIGNED
        self.teams: Dict[str, Dict[str, Any]] = {}
        if not os.path.exists(self.path):
            logger.warning("Ownership file %s not found; all incidents route to %r", self.path, UNASSIGNED)
            return
        with open(self.path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        self.default_team = str(data.get("default_team") or UNASSIGNED)
        for name, cfg in (data.get("teams") or {}).items():
            cfg = cfg or {}
            services = cfg.get("services") or []
            if not isinstance(services, list):
                raise ValueError(f"teams.{name}.services must be a list in {self.path}")
            self.teams[str(name)] = {
                "services": [str(s) for s in services],
                "tier": int(cfg["tier"]) if cfg.get("tier") is not None else None,
                "oncall": cfg.get("oncall"),
                "channel": cfg.get("channel"),
            }

    def known_team(self, team: str) -> bool:
        return team in self.teams or team == self.default_team

    def owner_of(self, service: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        for team, cfg in self.teams.items():
            if any(fnmatch.fnmatchcase(service, pat) for pat in cfg["services"]):
                return team, cfg
        return None

    def tier_for(self, services: Iterable[str]) -> Optional[int]:
        tiers = [
            owner[1]["tier"] for s in services
            if (owner := self.owner_of(s)) is not None and owner[1]["tier"] is not None
        ]
        return min(tiers) if tiers else None

    def contact(self, team: str) -> Dict[str, Any]:
        cfg = self.teams.get(team) or {}
        return {"oncall": cfg.get("oncall"), "channel": cfg.get("channel")}

    def route(self, source_counts: Dict[str, int]) -> Dict[str, Any]:
        ranked = sorted(source_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        primary: Optional[Tuple[str, str]] = None
        affected: Dict[str, str] = {}
        for service, _ in ranked:
            owner = self.owner_of(service)
            if owner is None:
                continue
            affected.setdefault(owner[0], service)
            if primary is None:
                primary = (owner[0], service)

        if primary is None:
            return {
                "team": self.default_team,
                "reason": "default_team",
                "service": ranked[0][0] if ranked else None,
                "also_affected": [],
                **self.contact(self.default_team),
            }
        team, service = primary
        return {
            "team": team,
            "reason": "ownership",
            "service": service,
            "also_affected": sorted(t for t in affected if t != team),
            **self.contact(team),
        }
