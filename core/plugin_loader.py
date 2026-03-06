from __future__ import annotations

import importlib
import os
import sys
from typing import Optional

from core.plugin_registry import PluginRegistry


def _split_csv(val: Optional[str]) -> list[str]:
    if not val:
        return []
    return [x.strip() for x in val.split(",") if x.strip()]


def load_plugins(registry: PluginRegistry) -> None:
    plugins_dir = os.getenv("PLUGINS_DIR", "/app/plugins")
    if os.path.isdir(plugins_dir) and plugins_dir not in sys.path:
        sys.path.insert(0, plugins_dir)

    module_names = _split_csv(os.getenv("PLUGIN_MODULES"))
    for mod in module_names:
        module = importlib.import_module(mod)
        register = getattr(module, "register", None)
        if callable(register):
            register(registry)
