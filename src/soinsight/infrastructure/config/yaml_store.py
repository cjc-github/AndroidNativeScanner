"""YAML configuration persistence and active-configuration management."""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

import yaml

from ...modules import ModuleCatalog
from .analysis_config import AnalysisConfig


_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class YamlConfigStore:
    def __init__(self, catalog: ModuleCatalog, config_dir: str | Path | None = None):
        configured = config_dir or os.environ.get("SOINSIGHT_CONFIG_DIR")
        self.config_dir = (
            Path(configured).expanduser()
            if configured
            else Path.home() / ".config" / "soinsight" / "configs"
        )
        self.catalog = catalog

    @property
    def active_file(self) -> Path:
        return self.config_dir.parent / "active-config"

    def path_for_name(self, name: str) -> Path:
        if not _NAME_PATTERN.fullmatch(name):
            raise ValueError(
                "Config name may contain letters, numbers, '.', '_' and '-' only"
            )
        return self.config_dir / f"{name}.yaml"

    def resolve(self, reference: str | Path) -> Path:
        candidate = Path(reference).expanduser()
        if candidate.exists():
            return candidate.resolve()
        if candidate.is_absolute() or candidate.parent != Path(".") or candidate.suffix:
            raise FileNotFoundError(f"Configuration file not found: {candidate}")
        managed = self.path_for_name(str(reference))
        if not managed.exists():
            raise FileNotFoundError(f"Configuration not found: {reference}")
        return managed.resolve()

    def load(self, reference: str | Path) -> AnalysisConfig:
        path = self.resolve(reference)
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML in {path}: {exc}") from exc
        return AnalysisConfig.from_mapping(payload, self.catalog, source=path)

    def create(self, name: str, *, force: bool = False) -> AnalysisConfig:
        path = self.path_for_name(name)
        if path.exists() and not force:
            raise FileExistsError(f"Configuration already exists: {path}")
        config = AnalysisConfig.from_mapping(
            {
                "schema_version": 1,
                "name": name,
                "description": "Custom SOInsight analysis configuration",
                "analysis": {
                    "modules": {
                        "basic": ["file", "elf", "symbols"],
                        "security": ["hardening"],
                    }
                },
                "runtime": {
                    "jobs": 1,
                    "timeout_seconds": 60,
                    "cache_enabled": True,
                    "fail_fast": False,
                },
                "output": {"format": "text"},
            },
            self.catalog,
            source=path,
        )
        self.save(config, path)
        return config

    def save(self, config: AnalysisConfig, path: Path | None = None) -> Path:
        destination = path or config.source or self.path_for_name(config.name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        text = yaml.safe_dump(
            config.to_mapping(),
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(destination)
        return destination.resolve()

    def list(self) -> list[Path]:
        if not self.config_dir.exists():
            return []
        return sorted(
            (*self.config_dir.glob("*.yaml"), *self.config_dir.glob("*.yml")),
            key=lambda item: item.name,
        )

    def use(self, reference: str | Path) -> AnalysisConfig:
        config = self.load(reference)
        assert config.source is not None
        self.active_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.active_file.with_suffix(".tmp")
        temporary.write_text(str(config.source.resolve()) + "\n", encoding="utf-8")
        temporary.replace(self.active_file)
        return config

    def current_path(self) -> Path | None:
        if not self.active_file.exists():
            return None
        value = self.active_file.read_text(encoding="utf-8").strip()
        if not value:
            return None
        path = Path(value).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"Active configuration no longer exists: {path}")
        return path.resolve()

    def current(self) -> AnalysisConfig | None:
        path = self.current_path()
        return self.load(path) if path else None

    def clear_current(self) -> None:
        if self.active_file.exists():
            self.active_file.unlink()

    def set_value(self, reference: str | Path, key: str, raw_value: str) -> AnalysisConfig:
        path = self.resolve(reference)
        payload = self._load_mapping(path)
        value = yaml.safe_load(raw_value)
        self._assign(payload, self._key_parts(key), value)
        config = AnalysisConfig.from_mapping(payload, self.catalog, source=path)
        self.save(config, path)
        return config

    def unset_value(self, reference: str | Path, key: str) -> AnalysisConfig:
        path = self.resolve(reference)
        payload = self._load_mapping(path)
        self._remove(payload, self._key_parts(key), key)
        config = AnalysisConfig.from_mapping(payload, self.catalog, source=path)
        self.save(config, path)
        return config

    @staticmethod
    def _load_mapping(path: Path) -> dict[str, Any]:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML in {path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError("configuration must be a mapping")
        return payload

    def _key_parts(self, key: str) -> list[str]:
        parts = [part for part in key.split(".") if part]
        if not parts:
            raise ValueError("Configuration key cannot be empty")
        if parts[0] == "capability_options" and len(parts) >= 3:
            known_ids = {
                capability.id
                for module in self.catalog.list()
                for capability in module.capabilities
            }
            capability_id = f"{parts[1]}.{parts[2]}"
            if capability_id in known_ids:
                return [parts[0], capability_id, *parts[3:]]
        return parts

    @staticmethod
    def _assign(payload: dict[str, Any], parts: list[str], value: object) -> None:
        current = payload
        for part in parts[:-1]:
            child = current.setdefault(part, {})
            if not isinstance(child, dict):
                raise ValueError(f"Cannot set nested key below non-mapping: {part}")
            current = child
        current[parts[-1]] = value

    @staticmethod
    def _remove(payload: dict[str, Any], parts: list[str], original_key: str) -> None:
        current = payload
        for part in parts[:-1]:
            child = current.get(part)
            if not isinstance(child, dict):
                raise KeyError(f"Configuration key not found: {original_key}")
            current = child
        if parts[-1] not in current:
            raise KeyError(f"Configuration key not found: {original_key}")
        del current[parts[-1]]
