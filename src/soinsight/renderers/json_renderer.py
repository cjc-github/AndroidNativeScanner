"""Stable machine-readable renderer."""

import json

from ..application import ApplicationResponse
from ..infrastructure.serialization import to_primitive
from .base import Renderer


class JsonRenderer(Renderer):
    format = "json"

    def render(self, response: ApplicationResponse) -> str:
        payload = {
            "result": to_primitive(response.result),
            "diagnostics": to_primitive(response.diagnostics),
            "exit_code": response.exit_code,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
