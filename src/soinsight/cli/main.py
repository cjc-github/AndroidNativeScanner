"""SOInsight V2 command-line framework."""

import argparse
import json
from pathlib import Path
import shutil
import sys
from typing import Sequence, TextIO

from ..analyzers import register_builtin_analyzers
from ..application import AnalysisRequest, AnalysisService, ApplicationResponse
from ..core.analyzer import AnalyzerRegistry
from ..core.models import Diagnostic, DiagnosticLevel
from ..core.profiles import ProfileRegistry
from ..core.runtime import AnalysisRuntime
from ..infrastructure.config import ConfigLoader
from ..infrastructure.plugins import PluginLoader
from ..renderers import RendererRegistry, create_default_renderer_registry
from ..version import __version__

_PHASE1_ANALYZER_COMMANDS = ("file", "elf", "symbols", "strings", "security")
_FUTURE_ANALYZER_COMMANDS = (
    "dwarf",
    "disasm",
    "cfg",
    "callgraph",
    "identify",
    "dynamic",
    "fuzz",
    "ai",
)


def _add_runtime_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument("-o", "--output", help="Output file, or '-' for stdout")
    parser.add_argument("-j", "--jobs", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--cache-dir", default=".soinsight/cache")
    parser.add_argument("--fail-fast", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soinsight",
        description="SOInsight V2 modular ELF analysis toolbox",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = subparsers.add_parser("scan", help="Run a composed analysis plan")
    scan.add_argument("target", type=Path)
    scan.add_argument(
        "--enable",
        default="",
        help="Comma-separated analyzer ids; defaults to registered analyzers",
    )
    scan.add_argument("--profile", default=None)
    _add_runtime_options(scan)
    scan.set_defaults(handler="analysis", analyzer_id=None)

    for command in _PHASE1_ANALYZER_COMMANDS:
        command_parser = subparsers.add_parser(
            command,
            help=f"Run the '{command}' analyzer when installed",
        )
        command_parser.add_argument("target", type=Path)
        _add_runtime_options(command_parser)
        command_parser.set_defaults(handler="analysis", analyzer_id=command)

    for command in _FUTURE_ANALYZER_COMMANDS:
        command_parser = subparsers.add_parser(
            command,
            help=f"Reserved V2 command shell for {command}",
        )
        command_parser.add_argument("target", type=Path, nargs="?")
        command_parser.set_defaults(handler="reserved")

    diff = subparsers.add_parser("diff", help="Reserved Binary Diff command shell")
    diff.add_argument("old", type=Path, nargs="?")
    diff.add_argument("new", type=Path, nargs="?")
    diff.set_defaults(handler="reserved")

    report = subparsers.add_parser("report", help="Validate or display an existing JSON result")
    report.add_argument("input", type=Path)
    report.add_argument("--format", choices=("text", "json"), default="json")
    report.add_argument("-o", "--output")
    report.set_defaults(handler="report")

    plugins = subparsers.add_parser("plugins", help="Inspect registered analyzers/plugins")
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

    config = subparsers.add_parser("config", help="Show framework configuration defaults")
    config.add_argument("action", choices=("show",), nargs="?", default="show")
    config.set_defaults(handler="config")

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


def _handle_analysis(
    args: argparse.Namespace,
    registry: AnalyzerRegistry,
    profiles: ProfileRegistry,
    renderers: RendererRegistry,
    stdout: TextIO,
) -> int:
    if args.analyzer_id:
        analyzer_ids = (args.analyzer_id,)
    elif args.enable:
        analyzer_ids = tuple(
            item.strip() for item in args.enable.split(",") if item.strip()
        )
    elif getattr(args, "profile", None):
        try:
            analyzer_ids = profiles.get(args.profile).analyzer_ids
        except KeyError as exc:
            response = ApplicationResponse(
                result=None,
                diagnostics=[
                    Diagnostic(
                        code="PROFILE_NOT_FOUND",
                        level=DiagnosticLevel.ERROR,
                        message=str(exc),
                    )
                ],
                exit_code=2,
            )
            return _render_response(
                response, args.format, args.output, renderers, stdout
            )
    else:
        analyzer_ids = registry.default_ids()

    try:
        config = ConfigLoader().load(
            jobs=args.jobs,
            timeout_seconds=args.timeout,
            quiet=args.quiet,
            verbose=args.verbose,
            no_color=args.no_color,
            cache_enabled=not args.no_cache,
            cache_dir=args.cache_dir,
            fail_fast=args.fail_fast,
        )
    except ValueError as exc:
        response = ApplicationResponse(
            result=None,
            diagnostics=[
                Diagnostic(
                    code="INVALID_CONFIGURATION",
                    level=DiagnosticLevel.ERROR,
                    message=str(exc),
                )
            ],
            exit_code=2,
        )
        return _render_response(
            response, args.format, args.output, renderers, stdout
        )

    service = AnalysisService(AnalysisRuntime(registry))
    response = service.execute(
        AnalysisRequest(
            target=args.target,
            analyzer_ids=analyzer_ids,
            profile=getattr(args, "profile", None),
        ),
        config,
    )
    return _render_response(response, args.format, args.output, renderers, stdout)


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
    stdout: TextIO,
) -> int:
    payload = {
        "soinsight_version": __version__,
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
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


def _handle_reserved(args: argparse.Namespace, stdout: TextIO) -> int:
    stdout.write(
        f"Command '{args.command}' is reserved by the V2 framework and has no "
        "concrete implementation yet.\n"
    )
    return 3


def main(
    argv: Sequence[str] | None = None,
    *,
    registry: AnalyzerRegistry | None = None,
    profiles: ProfileRegistry | None = None,
    renderers: RendererRegistry | None = None,
    stdout: TextIO | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    output_stream = stdout or sys.stdout
    analyzer_registry = registry or create_analyzer_registry()
    profile_registry = profiles or ProfileRegistry()
    renderer_registry = renderers or create_default_renderer_registry()

    if not args.command:
        parser.print_help(file=output_stream)
        return 0
    if args.handler == "analysis":
        return _handle_analysis(
            args,
            analyzer_registry,
            profile_registry,
            renderer_registry,
            output_stream,
        )
    if args.handler == "plugins":
        return _handle_plugins(args, analyzer_registry, output_stream)
    if args.handler == "doctor":
        return _handle_doctor(args, analyzer_registry, output_stream)
    if args.handler == "report":
        return _handle_report(args, output_stream)
    if args.handler == "cache":
        output_stream.write(f"Cache directory: {Path(args.cache_dir).resolve()}\n")
        return 0
    if args.handler == "config":
        output_stream.write("Runtime defaults: jobs=1 timeout=60 cache=true\n")
        return 0
    if args.handler == "reserved":
        return _handle_reserved(args, output_stream)
    parser.error(f"Unknown handler: {args.handler}")
    return 2
