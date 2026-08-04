"""Scan profile registry."""

from __future__ import annotations

from .model import ScanProfile


class ProfileRegistry:
    def __init__(self) -> None:
        self._profiles: dict[str, ScanProfile] = {}

    def register(self, profile: ScanProfile) -> None:
        if profile.id in self._profiles:
            raise ValueError(f"Profile already registered: {profile.id}")
        self._profiles[profile.id] = profile

    def get(self, profile_id: str) -> ScanProfile:
        try:
            return self._profiles[profile_id]
        except KeyError as exc:
            raise KeyError(f"Profile not found: {profile_id}") from exc

    def list(self) -> list[ScanProfile]:
        return [self._profiles[key] for key in sorted(self._profiles)]
