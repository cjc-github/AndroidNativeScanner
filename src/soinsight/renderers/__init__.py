"""Output renderer exports."""

from .base import Renderer
from .json_renderer import JsonRenderer
from .registry import RendererRegistry
from .text_renderer import TextRenderer


def create_default_renderer_registry() -> RendererRegistry:
    registry = RendererRegistry()
    registry.register(TextRenderer())
    registry.register(JsonRenderer())
    return registry


__all__ = [
    "JsonRenderer",
    "Renderer",
    "RendererRegistry",
    "TextRenderer",
    "create_default_renderer_registry",
]
