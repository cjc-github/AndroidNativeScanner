"""``automation.seed``: build a fuzz seed corpus from the recovered facts.

The corpus is generated from what the static analysis found: the container
formats the image carries, the protocols it speaks and the algorithm
constants it holds. An image with none of those facts still gets a corpus of
generic seeds, and every seed says which analyzer its rationale came from.

Publishing the corpus is opt-in; without it the seeds stay in the result.
"""

from typing import Optional

from ..core.analyzer import Analyzer, AnalyzerKind, AnalyzerMetadata
from ..core.models import (
    AnalysisResult,
    AnalysisStatus,
    AnalysisTarget,
    Diagnostic,
    DiagnosticLevel,
)
from ..infrastructure.seed_gen import build_seeds
from ..infrastructure.storage.artifact_store import FileArtifactStore

ANALYZER_ID = "automation.seed"

_DEFAULT_OPTIONS = {
    "min_seeds": 8,
    "max_seeds": 64,
    "size": 256,
    "publish": False,
    "corpus_root": "seed-corpus",
}


class AutomationSeedAnalyzer(Analyzer):
    """Generate a seed corpus from the recovered format, protocol and constants."""

    metadata = AnalyzerMetadata(
        id=ANALYZER_ID,
        name="Seed Generation Analyzer",
        version="1.0.0",
        description="Generate fuzz seeds from recovered formats, protocols and constants.",
        kind=AnalyzerKind.COLLECTOR,
        requires=(),
        optional_requires=(
            "advanced.file-format",
            "advanced.protocol",
            "advanced.constants",
        ),
        default_enabled=True,
    )

    def analyze(self, target: AnalysisTarget, context) -> AnalysisResult:
        options = _resolve_options(context)
        diagnostics: list[Diagnostic] = []

        format_facts = _facts(context, "advanced.file-format")
        protocol_facts = _facts(context, "advanced.protocol")
        constant_facts = _facts(context, "advanced.constants")

        target_bytes = _read_prefix(target.real_path, options["size"])
        if target_bytes is None:
            diagnostics.append(
                Diagnostic(
                    code="SEED_TARGET_UNREADABLE",
                    level=DiagnosticLevel.WARNING,
                    message="目标文件不可读，无法生成通用种子。",
                    analyzer_id=ANALYZER_ID,
                )
            )
            target_bytes = b""

        seeds, sources = build_seeds(
            target_bytes,
            format_facts=format_facts,
            protocol_facts=protocol_facts,
            constant_facts=constant_facts,
            min_seeds=options["min_seeds"],
            max_seeds=options["max_seeds"],
            size=options["size"],
        )

        artifacts = _publish(seeds, target, options, diagnostics)

        by_kind: dict[str, int] = {}
        for seed in seeds:
            by_kind[seed.kind] = by_kind.get(seed.kind, 0) + 1

        return AnalysisResult(
            analyzer_id=ANALYZER_ID,
            analyzer_version=self.metadata.version,
            status=AnalysisStatus.SUCCESS,
            data={
                "seed_count": len(seeds),
                "seeds": [seed.as_dict() for seed in seeds],
                "upstream_sources": sources,
                "target_bytes_used": "target-bytes" in sources,
                "targeted_count": sum(
                    1 for seed in seeds if seed.kind != "generic"
                ),
                "generic_count": sum(
                    1 for seed in seeds if seed.kind == "generic"
                ),
                "published": bool(artifacts),
                "artifacts": artifacts,
                "by_kind": by_kind,
            },
            diagnostics=diagnostics,
        )

    def format_text(self, result: AnalysisResult) -> Optional[str]:
        """List the generated seeds."""
        if result.status != AnalysisStatus.SUCCESS:
            return None
        data = result.data
        lines = [
            "=== Seed 生成 ===",
            f"种子数: {data.get('seed_count', 0)}",
            f"来源: {', '.join(data.get('upstream_sources') or ()) or '无'}",
        ]
        by_kind = data.get("by_kind") or {}
        if by_kind:
            summary = "，".join(f"{key} {value}" for key, value in sorted(by_kind.items()))
            lines.append(f"分类: {summary}")
        for seed in (data.get("seeds") or ())[:20]:
            lines.append(f"  - {seed['name']} ({seed['size']} 字节) {seed['rationale']}")
        remaining = len(data.get("seeds") or ()) - 20
        if remaining > 0:
            lines.append(f"  ... 其余 {remaining} 条")
        if not data.get("published"):
            lines.append("归档: 否（未开启 publish）")
        return "\n".join(lines)


def _facts(context, analyzer_id: str) -> dict | None:
    """The upstream result's data, when that analyzer took part."""
    result = context.optional(analyzer_id)
    if result is None:
        return None
    return dict(result.data or {})


def _read_prefix(path, limit: int) -> bytes | None:
    if path is None:
        return None
    try:
        with open(path, "rb") as stream:
            return stream.read(max(1, limit))
    except OSError:
        return None


def _publish(seeds, target, options: dict, diagnostics: list[Diagnostic]) -> list[dict]:
    """Write the corpus to disk when publishing is enabled."""
    if not options["publish"]:
        return []
    from pathlib import Path

    root = Path(options["corpus_root"]).expanduser()
    store = FileArtifactStore(root)
    namespace = f"seed/{target.name or 'target'}"
    artifacts: list[dict] = []
    for seed in seeds:
        key = f"{seed.name}.bin"
        try:
            store.put(namespace, key, seed.payload)
        except OSError as exc:
            diagnostics.append(
                Diagnostic(
                    code="SEED_PUBLISH_FAILED",
                    level=DiagnosticLevel.WARNING,
                    message=f"种子写入失败（{seed.name}）：{exc}",
                    analyzer_id=ANALYZER_ID,
                )
            )
            continue
        artifacts.append(
            {
                "namespace": namespace,
                "key": key,
                "size": seed.size,
                "sha256": seed.sha256,
                "path": str(root / namespace.replace("/", "_") / key),
            }
        )
    return artifacts


def _resolve_options(context) -> dict:
    """Read capability options with defaults and types enforced."""
    extra = getattr(getattr(context, "config", None), "extra", None) or {}
    declared = extra.get("capability_options", {}).get(ANALYZER_ID, {})
    resolved = dict(_DEFAULT_OPTIONS)

    for key, minimum, maximum in (
        ("min_seeds", 1, 4096),
        ("max_seeds", 1, 4096),
        ("size", 16, 4096),
    ):
        if key in declared:
            try:
                value = int(declared[key])
            except (TypeError, ValueError):
                value = _DEFAULT_OPTIONS[key]
            resolved[key] = max(minimum, min(value, maximum))

    publish = declared.get("publish")
    if isinstance(publish, bool):
        resolved["publish"] = publish
    elif isinstance(publish, str):
        resolved["publish"] = publish.strip().lower() in ("1", "true", "yes", "on")

    root = declared.get("corpus_root")
    if isinstance(root, str) and root.strip():
        resolved["corpus_root"] = root.strip()

    # ``max_seeds`` is the hard cap; the floor can never push past it.
    if resolved["min_seeds"] > resolved["max_seeds"]:
        resolved["min_seeds"] = resolved["max_seeds"]

    return resolved
