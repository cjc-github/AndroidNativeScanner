"""SOInsight V2 domain-oriented command-line framework."""

import argparse
import json
from pathlib import Path
import shutil
import sys
from typing import Any, Sequence, TextIO

import yaml

from ..analyzers import register_builtin_analyzers
from ..application import AnalysisRequest, AnalysisService, ApplicationResponse
from ..core.analyzer import AnalyzerRegistry
from ..core.models import Diagnostic, DiagnosticLevel
from ..core.profiles import ProfileRegistry
from ..core.runtime import AnalysisRuntime
from ..infrastructure.config import AnalysisConfig, ConfigLoader, YamlConfigStore
from ..infrastructure.plugins import PluginLoader
from ..modules import ModuleCatalog, create_builtin_module_catalog
from ..renderers import RendererRegistry, create_default_renderer_registry
from ..version import __version__

# Development-version aliases. The domain command tree is canonical.
_COMPATIBILITY_ALIASES = {
    "file": "basic.file",
    "elf": "basic.elf",
    "symbols": "basic.symbols",
    "strings": "advanced.strings",
    "dwarf": "basic.dwarf",
    "disasm": "basic.disasm",
    "cfg": "basic.cfg",
    "callgraph": "basic.callgraph",
}


def _add_runtime_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        metavar="NAME_OR_PATH",
        help="Use a managed or external YAML analysis configuration",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default=None,
        help="Output format (overrides YAML; default: text)",
    )
    parser.add_argument("-o", "--output", help="Output file, or '-' for stdout")
    parser.add_argument("-j", "--jobs", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--cache-dir", default=None)
    parser.add_argument("--fail-fast", action="store_true")


def _add_domain_commands(
    subparsers: argparse._SubParsersAction,
    catalog: ModuleCatalog,
) -> None:
    for module in catalog.list():
        module_parser = subparsers.add_parser(
            module.id,
            help=f"{module.name}: {module.description}",
            description=f"{module.name} — {module.description}",
        )
        capability_parsers = module_parser.add_subparsers(
            dest="capability_command",
            metavar="CAPABILITY",
        )
        module_parser.set_defaults(handler="module_help", help_parser=module_parser)

        for capability in module.capabilities:
            capability_parser = capability_parsers.add_parser(
                capability.command,
                help=f"{capability.name}: {capability.description}",
                description=f"{capability.name} — {capability.description}",
            )
            for argument in capability.target_arguments:
                capability_parser.add_argument(argument, type=Path)
            if capability.target_arguments == ("target",):
                _add_runtime_options(capability_parser)
                capability_parser.set_defaults(
                    handler="analysis",
                    analyzer_id=capability.id,
                    module_id=module.id,
                    capability_id=capability.id,
                )
            else:
                capability_parser.set_defaults(
                    handler="reserved",
                    module_id=module.id,
                    capability_id=capability.id,
                )


def _add_hidden_subparser(
    subparsers: argparse._SubParsersAction,
    name: str,
) -> argparse.ArgumentParser:
    """Register a compatibility command without advertising it in main help."""
    command_parser = subparsers.add_parser(name)
    subparsers._choices_actions = [
        action for action in subparsers._choices_actions if action.dest != name
    ]
    return command_parser


def _add_compatibility_aliases(subparsers: argparse._SubParsersAction) -> None:
    for command, analyzer_id in _COMPATIBILITY_ALIASES.items():
        command_parser = _add_hidden_subparser(subparsers, command)
        command_parser.add_argument("target", type=Path)
        _add_runtime_options(command_parser)
        command_parser.set_defaults(
            handler="analysis",
            analyzer_id=analyzer_id,
            compatibility_alias=True,
        )

    diff = _add_hidden_subparser(subparsers, "diff")
    diff.add_argument("old", type=Path, nargs="?")
    diff.add_argument("new", type=Path, nargs="?")
    diff.set_defaults(
        handler="reserved",
        module_id="automation",
        capability_id="automation.binary-diff",
        compatibility_alias=True,
    )


def build_parser(catalog: ModuleCatalog | None = None) -> argparse.ArgumentParser:
    module_catalog = catalog or create_builtin_module_catalog()
    parser = argparse.ArgumentParser(
        prog="soinsight",
        description=(
            "SOInsight V2 ELF analysis toolbox organized by product capability domains"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = subparsers.add_parser("scan", help="Run a composed cross-domain analysis plan")
    scan.add_argument("target", type=Path)
    scan.add_argument(
        "--module",
        default="",
        help="Comma-separated product modules, e.g. basic,security",
    )
    scan.add_argument(
        "--module-available",
        default="",
        help=argparse.SUPPRESS,
    )
    scan.add_argument(
        "--enable",
        default="",
        help="Comma-separated capability/analyzer ids",
    )
    scan.add_argument("--profile", default=None)
    _add_runtime_options(scan)
    scan.set_defaults(handler="analysis", analyzer_id=None)

    _add_domain_commands(subparsers, module_catalog)

    modules = subparsers.add_parser("modules", help="Inspect product capability modules")
    modules.add_argument("action", choices=("list", "show"), nargs="?", default="list")
    modules.add_argument("module_id", nargs="?")
    modules.add_argument("--format", choices=("text", "json"), default="text")
    modules.set_defaults(handler="modules")

    report = subparsers.add_parser(
        "report", help="Validate or display an existing JSON result"
    )
    report.add_argument("input", type=Path)
    report.add_argument("--format", choices=("text", "json"), default="json")
    report.add_argument("-o", "--output")
    report.set_defaults(handler="report")

    plugins = subparsers.add_parser(
        "plugins", help="Inspect registered technical extensions"
    )
    plugins.add_argument("action", choices=("list",), nargs="?", default="list")
    plugins.add_argument("--format", choices=("text", "json"), default="text")
    plugins.set_defaults(handler="plugins")

    doctor = subparsers.add_parser("doctor", help="Inspect framework environment")
    doctor.add_argument("--format", choices=("text", "json"), default="text")
    doctor.set_defaults(handler="doctor")

    cache = subparsers.add_parser("cache", help="Inspect the configured cache location")
    cache.add_argument("action", choices=("info",), nargs="?", default="info")
    cache.add_argument("--cache-dir", default=".soinsight/cache")
    cache.set_defaults(handler="cache")

    config = subparsers.add_parser(
        "config", help="Create, select, validate and edit YAML configurations"
    )
    config.add_argument(
        "--config-dir",
        help="Managed config directory (default: SOINSIGHT_CONFIG_DIR or user config dir)",
    )
    config_actions = config.add_subparsers(dest="config_action", metavar="ACTION")
    config.set_defaults(handler="config", config_action="help", help_parser=config)

    create = config_actions.add_parser("create", help="Create a managed configuration")
    create.add_argument("reference", metavar="NAME")
    create.add_argument("--force", action="store_true")

    listing = config_actions.add_parser("list", help="List managed configurations")
    listing.add_argument("--format", choices=("text", "json"), default="text")

    show = config_actions.add_parser("show", help="Print a configuration as YAML")
    show.add_argument("reference", metavar="NAME_OR_PATH")

    validate = config_actions.add_parser("validate", help="Validate a configuration")
    validate.add_argument("reference", metavar="NAME_OR_PATH")

    use = config_actions.add_parser("use", help="Set the active configuration")
    use.add_argument("reference", metavar="NAME_OR_PATH")

    config_actions.add_parser("current", help="Show the active configuration")
    config_actions.add_parser("clear", help="Clear the active configuration")

    set_value = config_actions.add_parser("set", help="Set a dotted YAML key")
    set_value.add_argument("reference", metavar="NAME_OR_PATH")
    set_value.add_argument("key", metavar="KEY")
    set_value.add_argument("value", metavar="YAML_VALUE")

    unset_value = config_actions.add_parser("unset", help="Remove a dotted YAML key")
    unset_value.add_argument("reference", metavar="NAME_OR_PATH")
    unset_value.add_argument("key", metavar="KEY")

    _add_compatibility_aliases(subparsers)
    return parser


def create_analyzer_registry() -> AnalyzerRegistry:
    registry = AnalyzerRegistry()
    register_builtin_analyzers(registry)
    PluginLoader().load(registry)
    return registry


def _write_output(text: str, output: str | None, stdout: TextIO) -> None:
    if not output or output == "-":
        stdout.write(text)
        return
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(destination)


def _render_response(
    response: ApplicationResponse,
    output_format: str,
    output: str | None,
    renderers: RendererRegistry,
    stdout: TextIO,
) -> int:
    text = renderers.get(output_format).render(response)
    _write_output(text, output, stdout)
    return response.exit_code


def _selection_error(
    code: str,
    message: str,
    output_format: str,
    output: str | None,
    renderers: RendererRegistry,
    stdout: TextIO,
) -> int:
    response = ApplicationResponse(
        result=None,
        diagnostics=[
            Diagnostic(code=code, level=DiagnosticLevel.ERROR, message=message)
        ],
        exit_code=2,
    )
    return _render_response(response, output_format, output, renderers, stdout)


def _unique(items: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(item for item in items if item))


def _rewrite_module_analysis_command(
    argv: Sequence[str] | None,
    catalog: ModuleCatalog,
) -> Sequence[str] | None:
    if not argv:
        return argv
    args = list(argv)
    command = args[0]
    try:
        module = catalog.get(command)
    except KeyError:
        return argv
    if len(args) == 1 or args[1] in {"-h", "--help"}:
        return argv
    capability_commands = {capability.command for capability in module.capabilities}
    if args[1] in capability_commands:
        return argv
    return ["scan", args[1], *args[2:], "--module-available", command]


def _resolve_analysis_config(
    args: argparse.Namespace,
    store: YamlConfigStore,
) -> AnalysisConfig | None:
    reference = getattr(args, "config", None)
    return store.load(reference) if reference else store.current()


def _resolve_analysis_selection(
    args: argparse.Namespace,
    registry: AnalyzerRegistry,
    profiles: ProfileRegistry,
    modules: ModuleCatalog,
    analysis_config: AnalysisConfig | None,
) -> tuple[str, ...]:
    # An explicit domain command always selects exactly one capability. YAML still
    # contributes runtime/output/options, but cannot broaden that command.
    if args.analyzer_id:
        return (args.analyzer_id,)

    selected: list[str] = []
    excluded: set[str] = set()
    if analysis_config:
        config_profile = analysis_config.analysis.profile
        if config_profile:
            selected.extend(profiles.get(config_profile).analyzer_ids)
        selected.extend(analysis_config.analysis.analyzer_ids(modules))
        excluded.update(analysis_config.analysis.exclude)

    profile_id = getattr(args, "profile", None)
    if profile_id:
        selected.extend(profiles.get(profile_id).analyzer_ids)

    module_expression = getattr(args, "module", "")
    if module_expression:
        module_ids = tuple(
            item.strip() for item in module_expression.split(",") if item.strip()
        )
        selected.extend(modules.analyzer_ids(module_ids))

    module_available_expression = getattr(args, "module_available", "")
    if module_available_expression:
        module_ids = tuple(
            item.strip()
            for item in module_available_expression.split(",")
            if item.strip()
        )
        selected.extend(
            analyzer_id
            for analyzer_id in modules.analyzer_ids(module_ids)
            if registry.contains(analyzer_id)
        )

    enable_expression = getattr(args, "enable", "")
    if enable_expression:
        selected.extend(
            item.strip() for item in enable_expression.split(",") if item.strip()
        )

    if not selected:
        selected.extend(registry.default_ids())
    return tuple(item for item in _unique(selected) if item not in excluded)


def _yaml_value(config: AnalysisConfig | None, section: str, key: str) -> Any:
    if config is None:
        return None
    values = config.runtime if section == "runtime" else config.output
    return values.get(key)


def _handle_analysis(
    args: argparse.Namespace,
    registry: AnalyzerRegistry,
    profiles: ProfileRegistry,
    modules: ModuleCatalog,
    renderers: RendererRegistry,
    config_store: YamlConfigStore,
    stdout: TextIO,
) -> int:
    try:
        analysis_config = _resolve_analysis_config(args, config_store)
    except (FileNotFoundError, OSError, ValueError, KeyError) as exc:
        return _selection_error(
            "INVALID_ANALYSIS_CONFIG", str(exc), args.format or "text", args.output,
            renderers, stdout,
        )

    output_format = args.format or _yaml_value(analysis_config, "output", "format") or "text"
    output = args.output
    if output is None:
        configured_output = _yaml_value(analysis_config, "output", "path")
        output = str(configured_output) if configured_output is not None else None

    try:
        analyzer_ids = _resolve_analysis_selection(
            args, registry, profiles, modules, analysis_config
        )
    except KeyError as exc:
        message = str(exc)
        code = "PROFILE_NOT_FOUND" if "Profile not found" in message else "MODULE_NOT_FOUND"
        return _selection_error(code, message, output_format, output, renderers, stdout)
    except ValueError as exc:
        return _selection_error(
            "INVALID_ANALYSIS_CONFIG", str(exc), output_format, output, renderers, stdout
        )

    yaml_runtime = analysis_config.runtime if analysis_config else {}
    cache_enabled = bool(yaml_runtime.get("cache_enabled", True))
    if args.no_cache:
        cache_enabled = False
    extra: dict[str, object] = {}
    if analysis_config:
        extra = {
            "analysis_config": analysis_config.name,
            "analysis_config_source": str(analysis_config.source or ""),
            "capability_options": analysis_config.capability_options,
        }
    try:
        runtime_config = ConfigLoader().load(
            jobs=args.jobs if args.jobs is not None else yaml_runtime.get("jobs"),
            timeout_seconds=(
                args.timeout
                if args.timeout is not None
                else yaml_runtime.get("timeout_seconds")
            ),
            quiet=args.quiet or bool(yaml_runtime.get("quiet", False)),
            verbose=args.verbose or bool(yaml_runtime.get("verbose", False)),
            no_color=args.no_color or bool(yaml_runtime.get("no_color", False)),
            cache_enabled=cache_enabled,
            cache_dir=(
                args.cache_dir
                if args.cache_dir is not None
                else yaml_runtime.get("cache_dir")
            ),
            fail_fast=args.fail_fast or bool(yaml_runtime.get("fail_fast", False)),
            extra=extra,
        )
    except (TypeError, ValueError) as exc:
        return _selection_error(
            "INVALID_CONFIGURATION", str(exc), output_format, output, renderers, stdout
        )

    service = AnalysisService(AnalysisRuntime(registry))
    effective_profile = getattr(args, "profile", None)
    if not effective_profile and analysis_config:
        effective_profile = analysis_config.analysis.profile
    response = service.execute(
        AnalysisRequest(
            target=args.target,
            analyzer_ids=analyzer_ids,
            profile=effective_profile,
        ),
        runtime_config,
    )
    return _render_response(response, output_format, output, renderers, stdout)


def _module_payload(module) -> dict[str, object]:
    return {
        "id": module.id,
        "name": module.name,
        "description": module.description,
        "capabilities": [
            {
                "id": capability.id,
                "command": capability.command,
                "name": capability.name,
                "description": capability.description,
                "target_arguments": list(capability.target_arguments),
            }
            for capability in module.capabilities
        ],
    }


def _handle_modules(
    args: argparse.Namespace,
    catalog: ModuleCatalog,
    stdout: TextIO,
) -> int:
    if args.action == "show":
        if not args.module_id:
            stdout.write("modules show requires MODULE_ID\n")
            return 2
        try:
            selected = [catalog.get(args.module_id)]
        except KeyError as exc:
            stdout.write(f"{exc}\n")
            return 2
    else:
        selected = catalog.list()

    if args.format == "json":
        stdout.write(
            json.dumps(
                [_module_payload(module) for module in selected],
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        )
        return 0

    for module in selected:
        stdout.write(
            f"{module.id}\t{module.name}\t{len(module.capabilities)} capabilities\n"
        )
        if args.action == "show":
            stdout.write(f"  {module.description}\n")
            for capability in module.capabilities:
                stdout.write(
                    f"  - {capability.command:<26} {capability.name} "
                    f"[{capability.id}]\n"
                )
    return 0


def _handle_plugins(
    args: argparse.Namespace,
    registry: AnalyzerRegistry,
    stdout: TextIO,
) -> int:
    metadata = registry.list()
    if args.format == "json":
        stdout.write(
            json.dumps(
                [
                    {
                        "id": item.id,
                        "name": item.name,
                        "version": item.version,
                        "kind": item.kind.value,
                        "requires": list(item.requires),
                    }
                    for item in metadata
                ],
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    elif metadata:
        for item in metadata:
            stdout.write(f"{item.id}\t{item.version}\t{item.name}\n")
    else:
        stdout.write("No analyzers registered. Framework shell is ready.\n")
    return 0


def _handle_doctor(
    args: argparse.Namespace,
    registry: AnalyzerRegistry,
    modules: ModuleCatalog,
    stdout: TextIO,
) -> int:
    payload = {
        "soinsight_version": __version__,
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "product_modules": len(modules.list()),
        "registered_analyzers": len(registry.list()),
        "legacy_tools": {
            name: shutil.which(name) for name in ("readelf", "nm", "strings")
        },
    }
    if args.format == "json":
        stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        stdout.write(f"SOInsight: {payload['soinsight_version']}\n")
        stdout.write(f"Python: {payload['python_version']}\n")
        stdout.write(f"Product modules: {payload['product_modules']}\n")
        stdout.write(f"Registered analyzers: {payload['registered_analyzers']}\n")
        for name, path in payload["legacy_tools"].items():
            stdout.write(f"{name}: {path or 'not found'}\n")
    return 0


def _handle_report(args: argparse.Namespace, stdout: TextIO) -> int:
    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        stdout.write(f"Report input error: {exc}\n")
        return 2
    if args.format == "json":
        text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    else:
        text = f"Valid JSON result: {args.input}\n"
    _write_output(text, args.output, stdout)
    return 0


def _config_yaml(config: AnalysisConfig) -> str:
    return yaml.safe_dump(
        config.to_mapping(),
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )


def _handle_config(
    args: argparse.Namespace,
    store: YamlConfigStore,
    stdout: TextIO,
) -> int:
    action = args.config_action
    if action == "help":
        args.help_parser.print_help(file=stdout)
        return 0
    try:
        if action == "create":
            config = store.create(args.reference, force=args.force)
            stdout.write(f"Created configuration '{config.name}': {config.source}\n")
        elif action == "list":
            active = store.current_path()
            paths = store.list()
            if args.format == "json":
                stdout.write(
                    json.dumps(
                        [
                            {
                                "name": path.stem,
                                "path": str(path.resolve()),
                                "active": active == path.resolve(),
                            }
                            for path in paths
                        ],
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n"
                )
            elif not paths:
                stdout.write(f"No managed configurations in {store.config_dir}\n")
            else:
                for path in paths:
                    marker = "*" if active == path.resolve() else " "
                    stdout.write(f"{marker} {path.stem}\t{path.resolve()}\n")
        elif action == "show":
            stdout.write(_config_yaml(store.load(args.reference)))
        elif action == "validate":
            config = store.load(args.reference)
            stdout.write(f"Configuration '{config.name}' is valid: {config.source}\n")
        elif action == "use":
            config = store.use(args.reference)
            stdout.write(f"Active configuration: {config.name} ({config.source})\n")
        elif action == "current":
            config = store.current()
            if config is None:
                stdout.write("No active configuration.\n")
            else:
                stdout.write(f"{config.name}\t{config.source}\n")
        elif action == "clear":
            store.clear_current()
            stdout.write("Active configuration cleared.\n")
        elif action == "set":
            config = store.set_value(args.reference, args.key, args.value)
            stdout.write(f"Updated {args.key} in '{config.name}'.\n")
        elif action == "unset":
            config = store.unset_value(args.reference, args.key)
            stdout.write(f"Removed {args.key} from '{config.name}'.\n")
        else:
            raise ValueError(f"Unknown config action: {action}")
        return 0
    except (FileNotFoundError, FileExistsError, KeyError, OSError, ValueError) as exc:
        stdout.write(f"Configuration error: {exc}\n")
        return 2


def _handle_reserved(args: argparse.Namespace, stdout: TextIO) -> int:
    capability_id = getattr(args, "capability_id", args.command)
    stdout.write(
        f"Capability '{capability_id}' is present in the V2 product framework "
        "but has no concrete implementation yet.\n"
    )
    return 3


def main(
    argv: Sequence[str] | None = None,
    *,
    registry: AnalyzerRegistry | None = None,
    profiles: ProfileRegistry | None = None,
    modules: ModuleCatalog | None = None,
    renderers: RendererRegistry | None = None,
    config_store: YamlConfigStore | None = None,
    stdout: TextIO | None = None,
) -> int:
    module_catalog = modules or create_builtin_module_catalog()
    parser = build_parser(module_catalog)
    raw_argv = sys.argv[1:] if argv is None else argv
    rewritten_argv = _rewrite_module_analysis_command(raw_argv, module_catalog)
    args = parser.parse_args(rewritten_argv)
    output_stream = stdout or sys.stdout
    analyzer_registry = registry or create_analyzer_registry()
    profile_registry = profiles or ProfileRegistry()
    renderer_registry = renderers or create_default_renderer_registry()
    yaml_config_store = config_store or YamlConfigStore(
        module_catalog, getattr(args, "config_dir", None)
    )

    if not args.command:
        parser.print_help(file=output_stream)
        return 0
    if args.handler == "module_help":
        args.help_parser.print_help(file=output_stream)
        return 0
    if args.handler == "analysis":
        return _handle_analysis(
            args,
            analyzer_registry,
            profile_registry,
            module_catalog,
            renderer_registry,
            yaml_config_store,
            output_stream,
        )
    if args.handler == "modules":
        return _handle_modules(args, module_catalog, output_stream)
    if args.handler == "plugins":
        return _handle_plugins(args, analyzer_registry, output_stream)
    if args.handler == "doctor":
        return _handle_doctor(
            args, analyzer_registry, module_catalog, output_stream
        )
    if args.handler == "report":
        return _handle_report(args, output_stream)
    if args.handler == "cache":
        output_stream.write(f"Cache directory: {Path(args.cache_dir).resolve()}\n")
        return 0
    if args.handler == "config":
        return _handle_config(args, yaml_config_store, output_stream)
    if args.handler == "reserved":
        return _handle_reserved(args, output_stream)
    parser.error(f"Unknown handler: {args.handler}")
    return 2
