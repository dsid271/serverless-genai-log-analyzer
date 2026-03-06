from __future__ import annotations

from typing import Any, Dict

from core.plugin_registry import PluginRegistry, PluginSpec


class ClientTagAnalyzer:
    async def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        incident = payload.get("incident", {})
        source = None
        details = incident.get("details") or {}
        if isinstance(details, dict):
            source = details.get("source")

        return {
            "analyzer": "client_tag",
            "tag": "telecom" if source else "generic",
        }


def register(registry: PluginRegistry) -> None:
    registry.register(
        PluginSpec(
            name="client_tag",
            kind="analyzer",
            factory=lambda: ClientTagAnalyzer(),
        )
    )
