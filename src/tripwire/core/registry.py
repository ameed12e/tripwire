"""Plugin registry for collectors and alert channels.

Plugins are discovered from two places:

1. Built-ins, registered explicitly below (work even from a source checkout).
2. Python entry points in the groups ``tripwire.collectors`` and
   ``tripwire.alerts``; any installed package can add plugins this way.

Non-Python plugins (Go, Rust, ...) are supported through the built-in
``subprocess`` collector; see docs/PLUGINS.md.
"""

from __future__ import annotations

import importlib
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Generic, TypeVar

from pydantic import ValidationError

from tripwire.core.config import ConfigError, PluginConfig

if TYPE_CHECKING:
    from tripwire.alerts.base import AlertChannel
    from tripwire.collectors.base import Collector
    from tripwire.core.plugin import PluginContext

T = TypeVar("T")

COLLECTOR_GROUP = "tripwire.collectors"
ALERT_GROUP = "tripwire.alerts"

_BUILTIN_COLLECTORS = {
    "filesystem": "tripwire.collectors.filesystem:FilesystemCollector",
    "subprocess": "tripwire.collectors.subprocess:SubprocessCollector",
}
_BUILTIN_ALERTS = {
    "telegram": "tripwire.alerts.telegram:TelegramChannel",
    "email": "tripwire.alerts.email:EmailChannel",
    "webhook": "tripwire.alerts.webhook:WebhookChannel",
}


def _import_ref(ref: str) -> type:
    module_name, _, attr = ref.partition(":")
    obj = getattr(importlib.import_module(module_name), attr)
    if not isinstance(obj, type):
        raise TypeError(f"{ref} is not a class")
    return obj


class Registry(Generic[T]):
    def __init__(self, group: str, builtins: dict[str, str]) -> None:
        self.group = group
        self._refs: dict[str, str] = dict(builtins)
        self._classes: dict[str, type[T]] = {}
        self._entry_points_loaded = False

    def register(self, name: str, cls: type[T]) -> None:
        """Register a plugin class programmatically (useful for tests and embedding)."""
        self._classes[name] = cls

    def _load_entry_points(self) -> None:
        if self._entry_points_loaded:
            return
        self._entry_points_loaded = True
        for ep in entry_points(group=self.group):
            self._refs.setdefault(ep.name, ep.value)

    def names(self) -> list[str]:
        self._load_entry_points()
        return sorted(set(self._refs) | set(self._classes))

    def get(self, name: str) -> type[T]:
        if name in self._classes:
            return self._classes[name]
        self._load_entry_points()
        ref = self._refs.get(name)
        if ref is None:
            raise ConfigError(
                f"unknown {self.group} plugin '{name}' (available: {', '.join(self.names())})"
            )
        cls: type[T] = _import_ref(ref)
        self._classes[name] = cls
        return cls


collectors: Registry[Collector] = Registry(COLLECTOR_GROUP, _BUILTIN_COLLECTORS)
alerts: Registry[AlertChannel] = Registry(ALERT_GROUP, _BUILTIN_ALERTS)


def build_collector(cfg: PluginConfig, ctx: PluginContext) -> Collector:
    cls = collectors.get(cfg.type)
    try:
        options = cls.Options.model_validate(cfg.options)
    except ValidationError as exc:
        raise ConfigError(f"collector '{cfg.instance_name}': invalid options\n{exc}") from exc
    return cls(cfg.instance_name, options, ctx)


def build_alert(cfg: PluginConfig, ctx: PluginContext) -> AlertChannel:
    cls = alerts.get(cfg.type)
    try:
        options = cls.Options.model_validate(cfg.options)
    except ValidationError as exc:
        raise ConfigError(f"alert '{cfg.instance_name}': invalid options\n{exc}") from exc
    return cls(cfg.instance_name, options, ctx)
