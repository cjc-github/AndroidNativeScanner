"""Renderer extension contract."""

from abc import ABC, abstractmethod

from ..application import ApplicationResponse


class Renderer(ABC):
    format: str

    @abstractmethod
    def render(self, response: ApplicationResponse) -> str:
        ...
