from pathlib import Path

import pytest
import yaml

from soinsight.infrastructure.config import YamlConfigStore
from soinsight.modules import create_builtin_module_catalog


def store(tmp_path):
    return YamlConfigStore(create_builtin_module_catalog(), tmp_path / "configs")


def test_create_load_list_set_and_unset(tmp_path):
    configs = store(tmp_path)
    created = configs.create("quick")

    assert created.source == tmp_path / "configs" / "quick.yaml"
    assert [path.name for path in configs.list()] == ["quick.yaml"]

    updated = configs.set_value("quick", "analysis.modules.basic", "[file, elf]")
    assert updated.analysis.modules["basic"] == ("file", "elf")
    updated = configs.set_value("quick", "runtime.jobs", "4")
    assert updated.runtime["jobs"] == 4
    updated = configs.set_value(
        "quick", "capability_options.advanced.strings.min_length", "6"
    )
    assert updated.capability_options["advanced.strings"]["min_length"] == 6

    updated = configs.unset_value("quick", "runtime.jobs")
    assert "jobs" not in updated.runtime
    assert configs.load("quick").name == "quick"


def test_use_current_clear_supports_external_yaml(tmp_path):
    configs = store(tmp_path)
    external = tmp_path / "external.yaml"
    external.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "name": "external",
                "analysis": {"modules": {"security": ["hardening"]}},
            }
        ),
        encoding="utf-8",
    )

    configs.use(external)
    assert configs.current_path() == external.resolve()
    assert configs.current().name == "external"

    configs.clear_current()
    assert configs.current() is None


def test_invalid_set_does_not_corrupt_existing_file(tmp_path):
    configs = store(tmp_path)
    configs.create("safe")
    path = configs.resolve("safe")
    before = path.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="runtime.jobs"):
        configs.set_value("safe", "runtime.jobs", "0")

    assert path.read_text(encoding="utf-8") == before


def test_rejects_multi_target_capability_in_scan_config(tmp_path):
    configs = store(tmp_path)
    configs.create("bad")

    with pytest.raises(ValueError, match="not compatible with single-target"):
        configs.set_value(
            "bad", "analysis.capabilities", "[automation.binary-diff]"
        )
