"""Renderer registry."""

from .base import Renderer


class RendererRegistry:
    def __init__(self) -> None:
        self._renderers: dict[str, Renderer] = {}

    def register(self, renderer: Renderer) -> None:
        if renderer.format in self._renderers:
            raise ValueError(f"Renderer already registered: {renderer.format}")
        self._renderers[renderer.format] = renderer

    def get(self, output_format: str) -> Renderer:
        try:
            return self._renderers[output_format]
        except KeyError as exc:
            raise ValueError(f"Unsupported output format: {output_format}") from exc

    def formats(self) -> tuple[str, ...]:
        return tuple(sorted(self._renderers))
