"""Rules over ``advanced.strings`` facts (V1 URL/Secret/Base64 migration).

V1 judged these strings inside analyzers; V2 splits the work the design
prescribes: ``advanced.strings`` supplies classified facts, these rules turn
them into severity and confidence judgments. Pattern labels stay identical to
V1 so reports stay comparable.
"""

from ..core.models import Confidence, Finding, Severity
from ..core.rules import Rule, RuleMetadata


_PRECISE_LABELS = frozenset(
    {"Google API Key", "OpenAI Key", "GitHub Token", "JWT"}
)


def _sensitive(label: str) -> tuple[Severity, Confidence, str]:
    """Per-label judgment table (mirrors the V1 risk weighting)."""
    if label == "JWT":
        return Severity.HIGH, Confidence.HIGH, (
            "JWT credentials must never be embedded; rotate the leaked token "
            "and load it from a secure store."
        )
    if label in _PRECISE_LABELS:
        return Severity.HIGH, Confidence.HIGH, (
            "Remove the embedded credential and load it from the environment "
            "or a secure store; rotate it first."
        )
    return Severity.MEDIUM, Confidence.LOW, (
        "The line resembles a credential assignment; verify whether it is a "
        "secret and move it into a secure configuration."
    )


class SensitiveStringRule(Rule):
    """Report API keys, tokens, JWTs and credential-like strings."""

    metadata = RuleMetadata(
        id="security.sensitive-string",
        name="Sensitive String Detection",
        description="API keys, tokens, JWTs and credential-like assignments.",
        requires=("advanced.strings",),
    )

    def evaluate(self, context) -> list[Finding]:
        return [
            self._finding(hit)
            for hit in _hits(context, "sensitive")
        ]

    def _finding(self, hit: dict) -> Finding:
        label = hit.get("label", "Unknown")
        severity, confidence, remediation = _sensitive(label)
        value = hit.get("value", "")
        return Finding(
            rule_id=f"{self.metadata.id}.{_slug(label)}",
            rule_version=self.metadata.version,
            title=f"Sensitive string detected ({label})",
            category="sensitive-string",
            severity=severity,
            confidence=confidence,
            message=f"A string matching '{label}' is embedded in the binary.",
            fingerprint=f"sensitive:{label}:{value}",
            locations=_locations(hit),
            evidence=(hit,),
            remediation=remediation,
        )


class HardcodedUrlRule(Rule):
    """Report hardcoded http(s) URLs as low-severity facts."""

    metadata = RuleMetadata(
        id="security.hardcoded-url",
        name="Hardcoded URL Detection",
        description="Hardcoded http(s) endpoints embedded in the binary.",
        requires=("advanced.strings",),
    )

    def evaluate(self, context) -> list[Finding]:
        return [
            Finding(
                rule_id=self.metadata.id,
                rule_version=self.metadata.version,
                title=_truncate(f"Hardcoded URL: {hit.get('value', '')}"),
                category="hardcoded-url",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                message=f"The binary embeds '{hit.get('value', '')}'.",
                fingerprint=f"url:{hit.get('value', '')}",
                locations=_locations(hit),
                evidence=(hit,),
                remediation=(
                    "Confirm the endpoint belongs to this product and treats "
                    "traffic confidentially."
                ),
            )
            for hit in _hits(context, "url")
        ]


class EncodedPayloadRule(Rule):
    """Report decodable Base64 blobs; usefulness is for the user to judge."""

    metadata = RuleMetadata(
        id="security.encoded-payload",
        name="Encoded Payload Detection",
        description="Decodable Base64 blobs with a printable preview.",
        requires=("advanced.strings",),
    )

    def evaluate(self, context) -> list[Finding]:
        return [
            Finding(
                rule_id=self.metadata.id,
                rule_version=self.metadata.version,
                title="Possibly encoded payload (Base64)",
                category="encoded-payload",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                message="A decodable Base64 blob is embedded in the binary.",
                fingerprint=f"base64:{hit.get('value', '')}",
                locations=_locations(hit),
                evidence=(hit,),
                remediation=(
                    "If the blob is part of the protocol, document it; "
                    "otherwise investigate a hidden payload."
                ),
            )
            for hit in _hits(context, "base64")
        ]


def _hits(context, category: str) -> list[dict]:
    strings = context.require("advanced.strings")
    classified = strings.data.get("classified", {}).get(category, {})
    return classified.get("hits", []) or []


def _locations(hit: dict) -> tuple[dict, ...]:
    location = {}
    if hit.get("offset"):
        location["offset"] = hit["offset"]
    if hit.get("section"):
        location["section"] = hit["section"]
    return (location,) if location else ()


def _slug(label: str) -> str:
    normalized = "".join(char if char.isalnum() else "-" for char in label.lower())
    return "-".join(part for part in normalized.split("-") if part)


def _truncate(text: str, limit: int = 100) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"
