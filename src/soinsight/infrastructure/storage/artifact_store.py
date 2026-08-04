"""Artifact storage contracts."""

from abc import ABC, abstractmethod
from pathlib import Path


class ArtifactStore(ABC):
    @abstractmethod
    def get(self, namespace: str, key: str) -> bytes | None:
        ...

    @abstractmethod
    def put(self, namespace: str, key: str, payload: bytes) -> None:
        ...

    @abstractmethod
    def delete(self, namespace: str, key: str) -> None:
        ...


class NullArtifactStore(ArtifactStore):
    def get(self, namespace: str, key: str) -> bytes | None:
        return None

    def put(self, namespace: str, key: str, payload: bytes) -> None:
        return None

    def delete(self, namespace: str, key: str) -> None:
        return None


class FileArtifactStore(ArtifactStore):
    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, namespace: str, key: str) -> Path:
        safe_namespace = namespace.replace("/", "_")
        safe_key = key.replace("/", "_")
        return self.root / safe_namespace / safe_key

    def get(self, namespace: str, key: str) -> bytes | None:
        path = self._path(namespace, key)
        return path.read_bytes() if path.is_file() else None

    def put(self, namespace: str, key: str, payload: bytes) -> None:
        path = self._path(namespace, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(payload)
        temporary.replace(path)

    def delete(self, namespace: str, key: str) -> None:
        path = self._path(namespace, key)
        if path.exists():
            path.unlink()
