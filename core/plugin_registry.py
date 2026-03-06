from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional, Protocol


class Connector(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...


class Detector(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...


class Analyzer(Protocol):
    async def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]: ...


@dataclass(frozen=True)
class PluginSpec:
    name: str
    kind: str
    factory: Callable[[], Any]


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: Dict[str, PluginSpec] = {}

    def register(self, spec: PluginSpec) -> None:
        key = f"{spec.kind}:{spec.name}"
        self._plugins[key] = spec

    def get(self, kind: str, name: str) -> Optional[PluginSpec]:
        return self._plugins.get(f"{kind}:{name}")

    def list(self, kind: Optional[str] = None) -> Iterable[PluginSpec]:
        if kind is None:
            return list(self._plugins.values())
        return [p for p in self._plugins.values() if p.kind == kind]
