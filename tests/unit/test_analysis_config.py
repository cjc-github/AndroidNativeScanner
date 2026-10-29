import pytest

from soinsight.infrastructure.config import AnalysisConfig
from soinsight.modules import create_builtin_module_catalog


def parse(payload):
    return AnalysisConfig.from_mapping(payload, create_builtin_module_catalog())


def base(analysis=None, **extra):
    payload = {"schema_version": 1, "name": "test", "analysis": analysis or {}}
    payload.update(extra)
    return payload


def test_expands_selected_module_capabilities_and_excludes():
    config = parse(
        base(
            {
                "modules": {"basic": ["file", "elf"]},
                "capabilities": ["security.hardening"],
                "exclude": ["basic.elf"],
            }
        )
    )

    assert config.analysis.analyzer_ids(create_builtin_module_catalog()) == (
        "basic.file",
        "security.hardening",
    )


def test_star_expands_all_single_target_capabilities():
    catalog = create_builtin_module_catalog()
    config = parse(base({"modules": {"security": "*"}}))

    assert config.analysis.analyzer_ids(catalog) == catalog.get("security").analyzer_ids


@pytest.mark.parametrize(
    "analysis,message",
    [
        ({"modules": {"missing": "*"}}, "Module not found"),
        ({"modules": {"basic": ["missing"]}}, "Capability not found"),
        ({"capabilities": ["missing.capability"]}, "Unknown capability"),
        (
            {"capabilities": ["automation.binary-diff"]},
            "not compatible with single-target",
        ),
    ],
)
def test_rejects_invalid_analysis_selection(analysis, message):
    with pytest.raises((KeyError, ValueError), match=message):
        parse(base(analysis))


def test_validates_runtime_output_and_capability_options():
    with pytest.raises(ValueError, match="runtime.jobs"):
        parse(base(runtime={"jobs": 0}))
    with pytest.raises(ValueError, match="output.format"):
        parse(base(output={"format": "xml"}))
    with pytest.raises(ValueError, match="Unknown capability_options"):
        parse(base(capability_options={"unknown.id": {"x": 1}}))

    config = parse(
        base(
            runtime={"jobs": 4},
            output={"format": "json"},
            capability_options={"advanced.strings": {"min_length": 6}},
        )
    )
    assert config.runtime["jobs"] == 4
    assert config.capability_options["advanced.strings"]["min_length"] == 6


def test_rejects_unknown_schema_fields():
    with pytest.raises(ValueError, match="Unknown configuration field"):
        parse(base(unknown=True))
    with pytest.raises(ValueError, match="Unknown analysis option"):
        parse(base({"moduels": {"basic": ["file"]}}))


def test_dynamic_execution_block_is_accepted_and_normalised():
    from soinsight.infrastructure.config.analysis_config import AnalysisConfig
    from soinsight.modules import create_builtin_module_catalog

    payload = {
        "name": "dyn",
        "schema_version": 1,
        "dynamic_execution": {
            "authorized": True,
            "allow_targets": ["/opt/samples/libfoo.so"],
            "timeout_seconds": 5,
        },
    }

    config = AnalysisConfig.from_mapping(
        payload, create_builtin_module_catalog()
    )

    assert config.dynamic_execution["authorized"] is True
    assert config.dynamic_execution["allow_targets"] == ["/opt/samples/libfoo.so"]
    assert config.dynamic_execution["timeout_seconds"] == 5


def test_dynamic_execution_defaults_to_absent():
    from soinsight.infrastructure.config.analysis_config import AnalysisConfig
    from soinsight.modules import create_builtin_module_catalog

    config = AnalysisConfig.from_mapping({"name": "x"}, create_builtin_module_catalog())

    assert config.dynamic_execution == {}


def test_dynamic_execution_rejects_unknown_or_malformed_options():
    import pytest

    from soinsight.infrastructure.config.analysis_config import AnalysisConfig
    from soinsight.modules import create_builtin_module_catalog

    catalog = create_builtin_module_catalog()

    with pytest.raises(ValueError, match="Unknown dynamic_execution option"):
        AnalysisConfig.from_mapping(
            {"name": "x", "dynamic_execution": {"auth": True}}, catalog
        )
    with pytest.raises(ValueError, match="authorized must be true or false"):
        AnalysisConfig.from_mapping(
            {"name": "x", "dynamic_execution": {"authorized": "yes"}}, catalog
        )
    with pytest.raises(ValueError, match="timeout_seconds"):
        AnalysisConfig.from_mapping(
            {"name": "x", "dynamic_execution": {"authorized": True, "timeout_seconds": 0}},
            catalog,
        )
