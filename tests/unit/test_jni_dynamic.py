"""Unit tests for the JNI dynamic-registration recovery."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from jni_builder import (  # noqa: E402
    DATA_REL_RO_ADDR,
    NAMED_FN_ADDR,
    ON_LOAD_ADDR,
    STRIPPED_FN_ADDR,
    build_jni_image,
    build_stripped_jni_image,
)

from soinsight.infrastructure.elf import parse_elf  # noqa: E402
from soinsight.infrastructure.jni_dynamic import find_dynamic_registrations  # noqa: E402


def _report(blob: bytes):
    path = Path("/tmp/jni_test.so")
    path.write_bytes(blob)
    elf = parse_elf(path)
    return find_dynamic_registrations(elf, blob)


def test_two_entries_are_recovered_with_symbols():
    blob = build_jni_image(
        [
            ("processData", "(Ljava/lang/String;)V", NAMED_FN_ADDR),
            ("getKey", "()J", STRIPPED_FN_ADDR),
        ],
        named_functions={NAMED_FN_ADDR: "native_process"},
    )

    report = _report(blob)

    assert report.on_load_present is True
    assert report.register_natives_imported is True
    assert len(report.registrations) == 2
    first = report.registrations[0]
    assert first.method_name == "processData"
    assert first.signature == "(Ljava/lang/String;)V"
    assert first.function_address == NAMED_FN_ADDR
    assert first.function_symbol == "native_process"
    assert first.qualified is False


def test_fully_qualified_name_is_reported_as_qualified():
    blob = build_jni_image(
        [("com.example.NativeLib.process", "(I)I", ON_LOAD_ADDR + 0x100)]
    )

    report = _report(blob)

    entry = report.registrations[0]
    assert entry.qualified is True
    assert entry.method_name == "com.example.NativeLib.process"


def test_stripped_image_still_recovers_addresses():
    blob = build_stripped_jni_image(
        [
            ("init", "()V", STRIPPED_FN_ADDR),
            ("run", "(Ljava/nio/ByteBuffer;)V", STRIPPED_FN_ADDR + 0x20),
        ]
    )

    report = _report(blob)

    assert report.registrations[0].function_symbol is None
    assert report.unnamed_function_count == 2
    assert report.registrations[0].function_address == STRIPPED_FN_ADDR


def test_image_without_on_load_and_import_reports_blocked():
    blob = build_jni_image(
        [("processData", "(Ljava/lang/String;)V", NAMED_FN_ADDR)],
        with_on_load=False,
        with_register_natives_import=False,
    )

    report = _report(blob)

    assert report.blocked_reason is not None
    assert report.registrations == ()


def test_array_slot_and_relocation_offsets_are_reported():
    blob = build_jni_image([("a", "()V", ON_LOAD_ADDR + 0x100)])

    report = _report(blob)

    entry = report.registrations[0]
    assert entry.array_slot == DATA_REL_RO_ADDR  # section offset == addr here
    assert len(entry.relocation_offsets) == 3


def test_partial_signature_is_rejected():
    """A slot triple whose middle pointer is not a descriptor must not match."""
    # Build a valid image, then corrupt the signature string in .rodata.
    blob = bytearray(
        build_jni_image([("processData", "(Ljava/lang/String;)V", NAMED_FN_ADDR)])
    )
    # Overwrite the signature string with a non-descriptor.
    sig_start = blob.find(b"(Ljava/lang/String;)V")
    assert sig_start > 0
    blob[sig_start : sig_start + 2] = b"xx"

    report = _report(bytes(blob))

    assert report.registrations == ()


def test_rel_relative_shape_is_recovered():
    """A 32-bit ARM image keeps the value inline; REL has no addend."""
    blob = build_jni_image(
        [("send", "(Ljava/lang/String;)V", NAMED_FN_ADDR)],
        named_functions={NAMED_FN_ADDR: "native_send"},
        relocation_shape="rel-relative",
    )

    report = _report(blob)

    assert len(report.registrations) == 1
    entry = report.registrations[0]
    assert entry.method_name == "send"
    assert entry.signature == "(Ljava/lang/String;)V"
    assert entry.function_symbol == "native_send"


def test_symbolic_function_pointer_is_recovered():
    """ARM names the function pointer by symbol: the slot holds S + A."""
    blob = build_jni_image(
        [("send", "(Ljava/lang/String;)V", NAMED_FN_ADDR)],
        named_functions={NAMED_FN_ADDR: "native_send"},
        relocation_shape="rel-abs32-symbol",
    )

    report = _report(blob)

    assert len(report.registrations) == 1
    entry = report.registrations[0]
    assert entry.method_name == "send"
    assert entry.function_address == NAMED_FN_ADDR
    assert entry.function_symbol == "native_send"
