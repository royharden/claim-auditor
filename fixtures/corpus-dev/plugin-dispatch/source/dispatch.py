"""Original DEV fixture: registry consumption and dynamic module attributes."""

import importlib

from registry import handlers

DEFAULT_PLUGIN = "disk"


def resolve(name):
    return handlers.get(name)


def __getattr__(name):
    plugin = importlib.import_module("plugins." + DEFAULT_PLUGIN)
    return getattr(plugin, name)
