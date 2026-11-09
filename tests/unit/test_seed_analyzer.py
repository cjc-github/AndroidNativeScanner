"""Unit tests for automation.seed."""

import pytest

from soinsight.analyzers.automation_seed import AutomationSeedAnalyzer
from soinsight.core.analyzer import AnalysisContext
from soinsight.core.models import AnalysisResult, AnalysisStatus, AnalysisTarget
from soinsight.infrastructure.config import RuntimeConfig


def _target(tmp_path=None):
    path = None
    size = 0
    if tmp_path is not None:
        path = tmp_path / "libsample.so"
        path.write_bytes(b"\x7fELF" + b"A" * 200)
        size = path.stat().st_size
    return AnalysisTarget(
        path=path,
        real_path=path,
        name="libsample.so",
        size=size,
        sha256="test",
    )


def _context(target, upstream=None, **options):
    context = AnalysisContext("run", target, RuntimeConfig(extra=options))
    for analyzer_id, data in (upstream or {}).items():
        context.add_result(
            AnalysisResult(
                analyzer_id=analyzer_id,
                analyzer_version="1.0.0",
                status=AnalysisStatus.SUCCESS,
                data=data,
            )
        )
    return context


def _format_facts():
    return {
        "formats": [
            {
                "format": "zip",
                "category": "archive",
                "magic": "504b0304",
                "offset": "0x1000",
                "verified": True,
            }
        ]
    }


def _protocol_facts():
    return {
        "protocols": [
            {
                "protocol": "mqtt",
                "family": "messaging",
                "strength": "corroborated",
                "evidence": [{"source": "string", "detail": "MQTT"}],
            }
        ]
    }


def _constant_facts():
    return {
        "hits": [
            {
                "algorithm": "AES",
                "family": "cipher",
                "offsets": ["0x40"],
                "sections": [".rodata"],
            }
        ]
    }


def test_analyzer_id_matches_the_catalog():
    from soinsight.modules import create_builtin_module_catalog

    capability = create_builtin_module_catalog().get("automation").get_capability(
        "seed"
    )
    assert capability.id == AutomationSeedAnalyzer.metadata.id


def test_container_seed_is_built_from_the_format_facts():
    target = _target()
    context = _context(target, {"advanced.file-format": _format_facts()})

    result = AutomationSeedAnalyzer().analyze(target, context)

    assert result.status == AnalysisStatus.SUCCESS
    kinds = {seed["kind"] for seed in result.data["seeds"]}
    assert "container" in kinds
    assert result.data["targeted_count"] >= 1
    assert "advanced.file-format" in result.data["upstream_sources"]


def test_protocol_and_constant_seeds_use_their_sources():
    target = _target()
    context = _context(
        target,
        {
            "advanced.protocol": _protocol_facts(),
            "advanced.constants": _constant_facts(),
        },
    )

    result = AutomationSeedAnalyzer().analyze(target, context)

    kinds = {seed["kind"] for seed in result.data["seeds"]}
    assert {"protocol", "constant"} <= kinds
    assert "advanced.protocol" in result.data["upstream_sources"]
    assert "advanced.constants" in result.data["upstream_sources"]


def test_without_upstream_facts_generic_seeds_are_used(tmp_path):
    target = _target(tmp_path)
    context = _context(target)

    result = AutomationSeedAnalyzer().analyze(target, context)

    assert result.data["target_bytes_used"] is True
    assert result.data["seed_count"] >= 8
    assert all(seed["kind"] == "generic" for seed in result.data["seeds"])


def test_max_seeds_caps_the_corpus():
    target = _target()
    context = _context(
        target,
        {"advanced.file-format": _format_facts()},
        capability_options={"automation.seed": {"max_seeds": 2}},
    )

    result = AutomationSeedAnalyzer().analyze(target, context)

    assert result.data["seed_count"] <= 2


def test_duplicate_seeds_are_removed():
    target = _target()
    duplicated = _format_facts()
    duplicated["formats"] = duplicated["formats"] * 2
    context = _context(target, {"advanced.file-format": duplicated})

    result = AutomationSeedAnalyzer().analyze(target, context)

    digests = [seed["sha256"] for seed in result.data["seeds"]]
    assert len(digests) == len(set(digests))


def test_publish_writes_the_corpus(tmp_path):
    target = _target(tmp_path)
    corpus = tmp_path / "corpus"
    context = _context(
        target,
        {"advanced.file-format": _format_facts()},
        capability_options={
            "automation.seed": {"publish": True, "corpus_root": str(corpus)}
        },
    )

    result = AutomationSeedAnalyzer().analyze(target, context)

    assert result.data["published"] is True
    written = [path for path in corpus.rglob("*.bin") if path.is_file()]
    assert written


def test_publish_is_off_by_default(tmp_path):
    target = _target(tmp_path)
    context = _context(target, {"advanced.file-format": _format_facts()})

    result = AutomationSeedAnalyzer().analyze(target, context)

    assert result.data["published"] is False
    assert result.data["artifacts"] == []


def test_format_text_lists_the_seeds():
    target = _target()
    context = _context(target, {"advanced.file-format": _format_facts()})

    result = AutomationSeedAnalyzer().analyze(target, context)
    text = AutomationSeedAnalyzer().format_text(result)

    assert "Seed 生成" in text
    assert "container-zip" in text


def test_format_text_is_none_for_a_failed_result():
    target = _target()
    context = _context(target)
    result = AutomationSeedAnalyzer().analyze(target, context)
    result.status = AnalysisStatus.FAILED

    assert AutomationSeedAnalyzer().format_text(result) is None


def test_seed_payload_starts_with_the_format_magic():
    from soinsight.infrastructure.seed_gen import container_seeds

    seeds = container_seeds(_format_facts())

    assert seeds[0].payload.startswith(b"PK\x03\x04")
