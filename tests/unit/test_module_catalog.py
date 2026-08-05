import pytest

from soinsight.modules import (
    CapabilityDefinition,
    ModuleCatalog,
    ModuleDefinition,
    create_builtin_module_catalog,
)


def test_builtin_catalog_uses_six_product_domains():
    catalog = create_builtin_module_catalog()

    assert [module.id for module in catalog.list()] == [
        "basic",
        "advanced",
        "security",
        "dynamic",
        "ai",
        "automation",
    ]
    assert catalog.get("basic").get_capability("elf").id == "basic.elf"
    assert catalog.get("automation").get_capability("binary-diff").target_arguments == (
        "old",
        "new",
    )


def test_catalog_rejects_capability_outside_module_namespace():
    module = ModuleDefinition(
        id="basic",
        name="Basic",
        description="",
        capabilities=(
            CapabilityDefinition("elf", "elf", "ELF", ""),
        ),
    )

    with pytest.raises(ValueError, match="namespaced"):
        ModuleCatalog((module,))


def test_scan_expansion_excludes_multi_target_capabilities():
    catalog = create_builtin_module_catalog()

    analyzer_ids = catalog.analyzer_ids(("automation",))

    assert "automation.binary-diff" not in analyzer_ids
    assert "automation.fuzz-target" in analyzer_ids
