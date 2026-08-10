"""SARIF 2.1.0 report renderer."""

import json

from ..application import ApplicationResponse
from .base import Renderer


class SarifRenderer(Renderer):
    format = "sarif"

    def render(self, response: ApplicationResponse) -> str:
        results = []
        if response.result is not None:
            for finding in response.result.findings:
                results.append(
                    {
                        "ruleId": finding.rule_id,
                        "level": "warning",
                        "message": {"text": finding.message},
                        "locations": [],
                    }
                )
        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "SOInsight"}},
                    "results": results,
                }
            ],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
