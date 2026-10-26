"""Generate an HTML report preview with DWARF signatures."""

import io
from pathlib import Path

from tests.conftest import (  # noqa: E402
    build_dwarf_sections,
    build_elf64_with_symbols,
)

from soinsight.application import AnalysisRequest, AnalysisService
from soilsight.core.analyzer import AnalyzerRegistry, register_builtin_analyzers  # noqa: F401
from soilsight.core.runtime import AnalysisRuntime
from soilsight.infrastructure.config import ConfigLoader, RuntimeConfig  # noqa: F401
from soinsight.cli.main import create_default_renderer_registry, create_builtin_profile_registry, create_builtin_module_catalog  # noqa: E401
from soinsight.renderers import create_default_renderer_registry

sys = __import__("sys")
sys.path.insert(0, "src")
sys.path.insert(0, "tests")

import sys
from pathlib import Path

sys.path.insert(0, "src")
sys.path.insert(0, "tests")

from conftest import (  # noqa: F401
    build_dwarf_sections,
    build_elf64_with_symbols,
)
from soinsight.application import AnalysisRequest, AnalysisService
from soilsight.core.analyzer import AnalyzerRegistry, register_builtin_analyzers  # noqa: F401
from soilsight.core.runtime import AnalysisRuntime
from soilsight.infrastructure.config import ConfigLoader, RuntimeConfig  # noqa: F401
from soilsight.cli.main import create_default_renderer_registry  # noqa: F401
from soilsight.renderers import create_default_renderer_registry

import io

symbols = [
    ("", 0, 3, 0xFFF1, 0, 0),
    ("add", 1, 2, 1, 0x1000, 0x40),
    ("_ZN7MyClass7processEPKci", 1, 2, 1, 0x1100, 0x60),
    ("Java_com_example_Foo_nativeInit", 1, 2, 1, 0x1200, 0x20),
]
path = Path("tmp_preview.so")
path.write_bytes(
    build_elf64_with_symbols(
        symbols, with_symtab=False, extra_sections=build_dwarf_sections()
    )
)
try:
    stdout = io.StringIO()
    registry = AnalyzerRegistry()
    register_builtin_analyzers(registry)
    runtime = AnalysisRuntime(registry)
    config = ConfigLoader().load(cache_enabled=False)
    service = AnalysisService(runtime)

    response = service.execute(
        AnalysisRequest(
            target=str(path),
            analyzer_ids=["basic.file", "basic.elf", "basic.symbols", "basic.dwarf"],
            profile=None,
        ),
        config,
    )

    renderers = create_default_renderer_registry()
    output_format = "html"
    result = renderers.get(output_format).render(response)
    html_path = Path("preview.html")
    html_path.write_text(result, encoding="utf-8")
    print(f"HTML preview written to: {html_path.resolve()}")
finally:
    path.unlink(missing_ok=True)
