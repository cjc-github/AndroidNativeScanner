"""Built-in SOInsight scan profiles."""

from .registry import ProfileRegistry, ScanProfile


def create_builtin_profile_registry() -> ProfileRegistry:
    registry = ProfileRegistry()
    registry.register(ScanProfile("quick", "Quick", ("basic.file", "basic.elf")))
    registry.register(ScanProfile("security", "Security", ("security.hardening",)))
    return registry
