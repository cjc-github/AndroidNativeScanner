"""Output renderer exports."""

from .base import Renderer
from .html_renderer import HtmlRenderer
from .json_renderer import JsonRenderer
from .markdown_renderer import MarkdownRenderer
from .registry import RendererRegistry
from .sarif_renderer import SarifRenderer
from .text_renderer import TextRenderer


def create_default_renderer_registry() -> RendererRegistry:
    registry = RendererRegistry()
    registry.register(TextRenderer())
    registry.register(JsonRenderer())
    registry.register(MarkdownRenderer())
    registry.register(HtmlRenderer())
    registry.register(SarifRenderer())
    return registry


__all__ = [
    "HtmlRenderer",
    "JsonRenderer",
    "MarkdownRenderer",
    "Renderer",
    "RendererRegistry",
    "SarifRenderer",
    "TextRenderer",
    "create_default_renderer_registry",
]
