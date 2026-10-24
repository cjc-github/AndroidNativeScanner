"""Unit tests for the JNI native-method name decoder."""

import pytest

from soinsight.infrastructure.elf import JniSymbol, decode_jni_symbol


@pytest.mark.parametrize(
    "name,expected",
    [
        (
            "Java_com_example_Foo_nativeInit",
            ("com.example", "Foo", "nativeInit", (), None),
        ),
        (
            "Java_com_example_Foo_nativeInit__ILjava_lang_String_2",
            ("com.example", "Foo", "nativeInit", ("int", "java.lang.String"), None),
        ),
        (
            "Java_com_example_My_1Class_do_1work__I_3I",
            ("com.example", "My_Class", "do_work", ("int", "int[]"), None),
        ),
        (
            "Java_MainActivity_onCreate__Landroid_os_Bundle_2",
            ("", "MainActivity", "onCreate", ("android.os.Bundle",), None),
        ),
        (
            "Java_C_f__IJ",
            ("", "C", "f", ("int", "long"), None),
        ),
        (
            "Java_com_example_Foo_bar__DLjava_lang_String_2_3I",
            (
                "com.example",
                "Foo",
                "bar",
                ("double", "java.lang.String", "int[]"),
                None,
            ),
        ),
        # A parenthesised JVM descriptor suffix is also accepted, and yields
        # the return type the bare argument list cannot provide.
        (
            "Java_C_f__(ILjava_lang_String_2)V",
            ("", "C", "f", ("int", "java.lang.String"), "void"),
        ),
    ],
)
def test_decode_jni_symbol(name, expected):
    decoded = decode_jni_symbol(name)

    assert decoded is not None
    assert (decoded.package, decoded.class_name, decoded.method,
            decoded.parameters, decoded.return_type) == expected


@pytest.mark.parametrize(
    "name",
    [
        "main",
        "JNI_OnLoad",
        "_init",
        "_fini",
        "_ZN3foo3barEi",
        "Java_",
        "Java_com_example_",
        "not_a_jni_symbol",
        "",
    ],
)
def test_decode_jni_symbol_rejects_non_jni_names(name):
    assert decode_jni_symbol(name) is None


def test_jni_qualified_name_omits_empty_package():
    symbol = JniSymbol(package="", class_name="MainActivity", method="onCreate")

    assert symbol.qualified_name == "MainActivity.onCreate"
    assert symbol.signature == "MainActivity.onCreate"


def test_jni_signature_renders_parameters():
    symbol = JniSymbol(
        package="com.example",
        class_name="Foo",
        method="nativeInit",
        parameters=("int", "java.lang.String"),
    )

    assert symbol.qualified_name == "com.example.Foo.nativeInit"
    assert symbol.signature == "com.example.Foo.nativeInit(int, java.lang.String)"


def test_jni_signature_renders_return_type_when_known():
    symbol = JniSymbol(
        package="com.example",
        class_name="Foo",
        method="read",
        parameters=("int",),
        return_type="java.lang.String",
    )

    assert symbol.signature == "java.lang.String com.example.Foo.read(int)"


def test_escaped_underscore_does_not_split_a_component():
    """``_1`` is the escape for a literal underscore inside a component."""
    decoded = decode_jni_symbol("Java_com_example_My_1Class_do_1work")

    assert decoded is not None
    assert (decoded.package, decoded.class_name, decoded.method) == (
        "com.example",
        "My_Class",
        "do_work",
    )
