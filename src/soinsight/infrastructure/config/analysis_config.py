"""Typed YAML analysis configuration for product-domain selections."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from ...modules import ModuleCatalog


SUPPORTED_SCHEMA_VERSION = 1
_ALLOWED_RUNTIME_KEYS = {
    "jobs",
    "timeout_seconds",
    "quiet",
    "verbose",
    "no_color",
    "cache_enabled",
    "cache_dir",
    "fail_fast",
}
_ALLOWED_OUTPUT_KEYS = {"format", "path"}
_ALLOWED_ROOT_KEYS = {
    "schema_version", "name", "description", "analysis", "runtime", "output",
    "capability_options",
}
_ALLOWED_ANALYSIS_KEYS = {"modules", "capabilities", "exclude", "profile"}


def _expect_mapping(value: object, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be a mapping")
    return {str(key): item for key, item in value.items()}


def _expect_string_list(value: object, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a string or list of strings")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"{field_name} must contain non-empty strings")
    return tuple(item.strip() for item in value)


@dataclass(frozen=True)
class AnalysisSelectionConfig:
    modules: dict[str, tuple[str, ...]] = field(default_factory=dict)
    capabilities: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    profile: str | None = None

    def analyzer_ids(self, catalog: ModuleCatalog) -> tuple[str, ...]:
        selected: list[str] = []
        for module_id, requested in self.modules.items():
            module = catalog.get(module_id)
            if requested == ("*",):
                selected.extend(module.analyzer_ids)
                continue
            for token in requested:
                capability = module.get_capability(token)
                if capability.target_arguments != ("target",):
                    raise ValueError(
                        f"Capability '{capability.id}' is not compatible with "
                        "single-target scan configuration"
                    )
                selected.append(capability.id)

        known = {
            capability.id: capability
            for module in catalog.list()
            for capability in module.capabilities
        }
        for capability_id in self.capabilities:
            try:
                capability = known[capability_id]
            except KeyError as exc:
                raise ValueError(f"Unknown capability: {capability_id}") from exc
            if capability.target_arguments != ("target",):
                raise ValueError(
                    f"Capability '{capability_id}' is not compatible with "
                    "single-target scan configuration"
                )
            selected.append(capability_id)

        excluded = set(self.exclude)
        unknown_excluded = excluded.difference(known)
        if unknown_excluded:
            raise ValueError(
                "Unknown excluded capability: " + ", ".join(sorted(unknown_excluded))
            )
        return tuple(dict.fromkeys(item for item in selected if item not in excluded))


@dataclass(frozen=True)
class AnalysisConfig:
    name: str
    description: str = ""
    schema_version: int = SUPPORTED_SCHEMA_VERSION
    analysis: AnalysisSelectionConfig = field(default_factory=AnalysisSelectionConfig)
    runtime: dict[str, object] = field(default_factory=dict)
    output: dict[str, object] = field(default_factory=dict)
    capability_options: dict[str, dict[str, object]] = field(default_factory=dict)
    source: Path | None = None

    @classmethod
    def from_mapping(
        cls,
        payload: object,
        catalog: ModuleCatalog,
        *,
        source: Path | None = None,
    ) -> "AnalysisConfig":
        root = _expect_mapping(payload, "configuration")
        unknown_root = set(root).difference(_ALLOWED_ROOT_KEYS)
        if unknown_root:
            raise ValueError(
                "Unknown configuration field: " + ", ".join(sorted(unknown_root))
            )
        schema_version = root.get("schema_version", SUPPORTED_SCHEMA_VERSION)
        if schema_version != SUPPORTED_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported schema_version {schema_version!r}; "
                f"expected {SUPPORTED_SCHEMA_VERSION}"
            )
        name = root.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("name must be a non-empty string")
        description = root.get("description", "")
        if not isinstance(description, str):
            raise ValueError("description must be a string")

        analysis_payload = _expect_mapping(root.get("analysis"), "analysis")
        unknown_analysis = set(analysis_payload).difference(_ALLOWED_ANALYSIS_KEYS)
        if unknown_analysis:
            raise ValueError(
                "Unknown analysis option: " + ", ".join(sorted(unknown_analysis))
            )
        modules_payload = _expect_mapping(
            analysis_payload.get("modules"), "analysis.modules"
        )
        modules: dict[str, tuple[str, ...]] = {}
        for module_id, value in modules_payload.items():
            catalog.get(module_id)
            requested = _expect_string_list(
                value, f"analysis.modules.{module_id}"
            )
            if not requested:
                raise ValueError(
                    f"analysis.modules.{module_id} cannot be empty; use '*' for all"
                )
            if "*" in requested and requested != ("*",):
                raise ValueError(
                    f"analysis.modules.{module_id} cannot combine '*' with names"
                )
            modules[module_id] = requested

        profile = analysis_payload.get("profile")
        if profile is not None and (not isinstance(profile, str) or not profile.strip()):
            raise ValueError("analysis.profile must be a non-empty string")
        selection = AnalysisSelectionConfig(
            modules=modules,
            capabilities=_expect_string_list(
                analysis_payload.get("capabilities"), "analysis.capabilities"
            ),
            exclude=_expect_string_list(
                analysis_payload.get("exclude"), "analysis.exclude"
            ),
            profile=profile.strip() if isinstance(profile, str) else None,
        )
        selection.analyzer_ids(catalog)

        runtime = _expect_mapping(root.get("runtime"), "runtime")
        unknown_runtime = set(runtime).difference(_ALLOWED_RUNTIME_KEYS)
        if unknown_runtime:
            raise ValueError(
                "Unknown runtime option: " + ", ".join(sorted(unknown_runtime))
            )
        _validate_runtime(runtime)

        output = _expect_mapping(root.get("output"), "output")
        unknown_output = set(output).difference(_ALLOWED_OUTPUT_KEYS)
        if unknown_output:
            raise ValueError(
                "Unknown output option: " + ", ".join(sorted(unknown_output))
            )
        _validate_output(output)

        options_payload = _expect_mapping(
            root.get("capability_options"), "capability_options"
        )
        known_ids = {
            capability.id
            for module in catalog.list()
            for capability in module.capabilities
        }
        capability_options: dict[str, dict[str, object]] = {}
        for capability_id, options in options_payload.items():
            if capability_id not in known_ids:
                raise ValueError(f"Unknown capability_options id: {capability_id}")
            capability_options[capability_id] = _expect_mapping(
                options, f"capability_options.{capability_id}"
            )

        return cls(
            name=name.strip(),
            description=description,
            schema_version=schema_version,
            analysis=selection,
            runtime=runtime,
            output=output,
            capability_options=capability_options,
            source=source,
        )

    def to_mapping(self) -> dict[str, object]:
        analysis: dict[str, object] = {
            "modules": {
                module_id: requested[0]
                if requested == ("*",)
                else list(requested)
                for module_id, requested in self.analysis.modules.items()
            }
        }
        if self.analysis.profile:
            analysis["profile"] = self.analysis.profile
        if self.analysis.capabilities:
            analysis["capabilities"] = list(self.analysis.capabilities)
        if self.analysis.exclude:
            analysis["exclude"] = list(self.analysis.exclude)
        payload: dict[str, object] = {
            "schema_version": self.schema_version,
            "name": self.name,
            "description": self.description,
            "analysis": analysis,
            "runtime": dict(self.runtime),
            "output": dict(self.output),
        }
        if self.capability_options:
            payload["capability_options"] = self.capability_options
        return payload


def _validate_runtime(runtime: Mapping[str, object]) -> None:
    for key in ("jobs", "timeout_seconds"):
        if key in runtime and (
            not isinstance(runtime[key], int)
            or isinstance(runtime[key], bool)
            or runtime[key] < 1
        ):
            raise ValueError(f"runtime.{key} must be an integer >= 1")
    for key in (
        "quiet",
        "verbose",
        "no_color",
        "cache_enabled",
        "fail_fast",
    ):
        if key in runtime and not isinstance(runtime[key], bool):
            raise ValueError(f"runtime.{key} must be a boolean")
    if "cache_dir" in runtime and not isinstance(runtime["cache_dir"], str):
        raise ValueError("runtime.cache_dir must be a string")


def _validate_output(output: Mapping[str, object]) -> None:
    if "format" in output and output["format"] not in ("text", "json"):
        raise ValueError("output.format must be 'text' or 'json'")
    if "path" in output and not isinstance(output["path"], str):
        raise ValueError("output.path must be a string")
