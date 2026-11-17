"""Shared plugin plumbing: context passed to every plugin and the base class."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel, ConfigDict

from tripwire.core.config import TripwireConfig


class PluginOptions(BaseModel):
    """Base class for plugin options. Unknown keys are rejected."""

    model_config = ConfigDict(extra="forbid")


@dataclass(frozen=True)
class PluginContext:
    config: TripwireConfig

    @property
    def host_name(self) -> str:
        return self.config.host_name


OptionsT = TypeVar("OptionsT", bound=PluginOptions)


class Plugin(Generic[OptionsT]):
    """Common base for collectors and alert channels."""

    Options: ClassVar[type[PluginOptions]] = PluginOptions

    def __init__(self, name: str, options: OptionsT, ctx: PluginContext) -> None:
        self.name = name
        self.options = options
        self.ctx = ctx

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "type": type(self).__name__}
