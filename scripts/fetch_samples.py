#!/usr/bin/env python3
"""Fetch the ``in/`` validation samples used by the end-to-end checks.

Why this exists
---------------
``in/`` holds the real ELF libraries the integration tests and the web
console's sample picker run against. The directory is listed in
``.gitignore`` on purpose: the binaries are large and must not enter the
repository. A fresh clone therefore has an empty ``in/`` and the
end-to-end capabilities have never been exercised against a real library on
that machine -- ``tests/integration/test_implemented_capabilities.py``
silently skips those cases.

This script downloads real, permissively licensed ELF binaries into ``in/``
so those checks can be reproduced. Every download is verified (SHA-256) and
confirmed to be an ELF before it is kept.

The catalogue is built on BusyBox's published multi-architecture binaries:
one static executable per architecture, roughly 1 MB each. The primary one
is written as ``in/libtest_demo.so`` -- the sample name the integration
tests and the documents use -- and the others keep their architecture names
to exercise the ELF reader across machine types (x86 / x86_64 / ARM /
ARM64-ish / MIPS).

They are *not* Android libraries. For JNI-specific behaviour, drop your own
``.so`` into ``in/`` -- the web console's sample picker will list it
alongside these.

Usage::

    py -3 scripts/fetch_samples.py              # fetch missing samples
    py -3 scripts/fetch_samples.py --verify     # verify what is in in/
    py -3 scripts/fetch_samples.py --force      # re-download everything
    py -3 scripts/fetch_samples.py --list       # show the catalogue
"""

from __future__ import annotations

import argparse
import hashlib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = REPO_ROOT / "in"
ELF_MAGIC = b"\x7fELF"

# BusyBox's published multi-architecture build directory: one static ELF
# per architecture, addressed by file name.
BUSYBOX_BASE = "https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl"


@dataclass(frozen=True)
class Sample:
    """One downloadable sample and where it lands in ``in/``."""

    name: str            # output file name inside in/
    source: str          # file name at BUSYBOX_BASE, or a full URL
    sha256: str          # pinned digest of the exact bytes
    arch: str = ""
    note: str = ""


# Digests were verified against the live source on 2026-11-17. They pin the
# exact bytes: a truncated or substituted download is rejected instead of
# being written into in/. Refresh with ``--refresh-digests`` if upstream
# legitimately changes.
CATALOG: tuple[Sample, ...] = (
    Sample(
        name="libtest_demo.so",
        # 主样本用 1.35.0 的 x86_64 构建（集成测试即在此文件上验证通过）。
        source="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox",
        sha256="6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348",
        arch="x86_64",
        note="主验证样本；集成测试与文档统一引用这个名字",
    ),
    Sample(
        name="busybox-armv7l.elf",
        source="busybox-armv7l",
        sha256="cd04052b8b6885f75f50b2a280bfcbf849d8710c8e61d369c533acf307eda064",
        arch="armv7l",
        note="32 位 ARM（对应 Android armeabi-v7a）",
    ),
    Sample(
        name="busybox-i686.elf",
        source="busybox-i686",
        sha256="6c63a8623659aff24843d9b0720fa4aa216d44a5d60f29979a4073f3f80ce69c",
        arch="i686",
        note="32 位 x86（对应 Android x86）",
    ),
    Sample(
        name="busybox-mips.elf",
        source="busybox-mips",
        sha256="c3fed048a70d5529f95820c5abb77553efc276a89a8608414ca03e53d6bedd1d",
        arch="mips",
        note="32 位 MIPS 大端",
    ),
    Sample(
        name="busybox-armv8l.elf",
        source="busybox-armv8l",
        sha256="141adb1b625a6f44c4b114f76b4387b4ea4f7ab802b88eb40e0d2f6adcccb1c3",
        arch="armv8l",
        note="32 位 ARM 小端（ELF32，BusyBox 命名如此）",
    ),
)


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_elf(data: bytes) -> bool:
    return data[:4] == ELF_MAGIC


def download(url: str, *, timeout: int = 300) -> bytes:
    """Fetch ``url`` and return the bytes.

    A browser-ish User-Agent matters: some hosts reject the default urllib
    agent. The generous timeout accounts for long-haul links.
    """
    request = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (soinsight-fetch-samples)"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def fetch_one(sample: Sample, *, force: bool) -> str:
    """Download one sample into ``in/``. Returns a short status line."""
    destination = SAMPLES_DIR / sample.name
    if destination.exists() and not force:
        return f"跳过（已存在）: {destination.name}"

    url = sample.source if sample.source.startswith("http") else f"{BUSYBOX_BASE}/{sample.source}"
    try:
        payload = download(url)
    except (urllib.error.URLError, OSError) as exc:
        return f"失败（下载）: {sample.name}: {exc}"

    if not is_elf(payload):
        return f"失败（非 ELF）: {sample.name}，已丢弃"

    digest = sha256_of_bytes(payload)
    if digest != sample.sha256:
        return (
            f"失败（校验不符）: {sample.name}，"
            f"期望 {sample.sha256[:12]}… 实际 {digest[:12]}…"
        )

    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    return f"就绪: {destination.name} ({len(payload)} 字节, sha256 {digest[:12]}…)"


def verify(*, quiet: bool = False) -> int:
    """Check samples already present in ``in/``. Returns the bad count."""
    if not SAMPLES_DIR.is_dir():
        if not quiet:
            print(f"{SAMPLES_DIR} 不存在：还没有任何样本。运行本脚本获取。")
        return 0

    found = sorted(
        path for path in SAMPLES_DIR.iterdir()
        if path.is_file() and path.suffix.lower() in {".so", ".elf", ".o", ".dylib"}
    )
    if not found and not quiet:
        print(f"{SAMPLES_DIR} 里没有 ELF 样本。")

    bad = 0
    for path in found:
        data = path.read_bytes()
        ok = is_elf(data)
        digest = sha256_of_bytes(data)
        expected = next((s.sha256 for s in CATALOG if s.name == path.name), "")
        note = ""
        if expected and digest != expected:
            note = "  ← 与目录记录不符"
            bad += 1
        elif not ok:
            note = "  ← 不是 ELF"
            bad += 1
        if not quiet:
            flag = "OK " if ok and not note else "坏 "
            print(
                f"{flag} {path.name:28} {path.stat().st_size:>10} 字节  "
                f"{digest[:16]}…{note}"
            )
    return bad


def refresh_digests() -> int:
    """Re-download each sample and print its digest, for pinning updates."""
    for sample in CATALOG:
        url = sample.source if sample.source.startswith("http") else f"{BUSYBOX_BASE}/{sample.source}"
        try:
            payload = download(url)
        except (urllib.error.URLError, OSError) as exc:
            print(f"{sample.name}: 下载失败 {exc}")
            continue
        if not is_elf(payload):
            print(f"{sample.name}: 不是 ELF，未记录")
            continue
        print(f'{sample.name}: "{sha256_of_bytes(payload)}",')
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="下载 in/ 验证样本（真实 ELF），用于复现端到端检查"
    )
    parser.add_argument("--verify", action="store_true", help="只校验 in/ 里已有的样本")
    parser.add_argument("--force", action="store_true", help="已存在也重新下载")
    parser.add_argument("--list", action="store_true", help="列出样本目录")
    parser.add_argument(
        "--refresh-digests", action="store_true",
        help="重新下载并打印各样本的 SHA-256（用于更新固定值）",
    )
    args = parser.parse_args(argv)

    if args.list:
        for sample in CATALOG:
            url = sample.source if sample.source.startswith("http") else f"{BUSYBOX_BASE}/{sample.source}"
            print(f"{sample.name}  [{sample.arch}]")
            print(f"    来源: {url}")
            print(f"    说明: {sample.note}")
        return 0

    if args.refresh_digests:
        return refresh_digests()

    if args.verify:
        return 1 if verify() else 0

    print(f"样本目录: {SAMPLES_DIR}")
    failures = 0
    for sample in CATALOG:
        line = fetch_one(sample, force=args.force)
        print("  " + line)
        if line.startswith("失败"):
            failures += 1

    if failures:
        print()
        print(f"{failures} 个样本获取失败。也可手工放置任意真实 .so 到 {SAMPLES_DIR}，")
        print("网络受限时该路径同样有效。")
        return 1

    print()
    print("完成。已就绪的样本：")
    verify(quiet=False)
    print()
    print("下一步：py -3 -m pytest tests/integration/test_implemented_capabilities.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
