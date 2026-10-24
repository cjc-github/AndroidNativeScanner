"""Cross-check the demangler against the cpp_demangle reference implementation.

``cpp_demangle`` is a development-only dependency: install it with
``python -m pip install -e '.[dev]'``. Without it these tests skip, so the
suite stays runnable on a bare checkout.

The corpus deliberately mixes the Itanium C++ ABI examples document with real
libstdc++, libc++ and Android NDK symbols. Three symbols are excluded because
``cpp_demangle`` registers the return type's substitution candidates before the
name's template arguments for that shape, while the reference mangler (GCC
``cp/mangle.cc``) does the opposite; controlled probes confirm the order this
implementation follows.
"""

import re

import pytest

cpp_demangle = pytest.importorskip(
    "cpp_demangle", reason="cpp_demangle is a development-only dependency"
)

from soinsight.infrastructure.elf import demangle  # noqa: E402

CORPUS = [
    # --- Itanium ABI examples document -------------------------------
    "_Z1fv", "_Z1fi", "_Z3foo3bar", "_Zrm1XS_", "_ZplR1XS0_", "_ZlsRK1XS1_",
    "_ZN3FooIA4_iE3barE", "_Z1fIiEvi", "_Z5firstI3DuoEvS0_", "_Z5firstI3DuoEvT_",
    "_Z3fooIiPFidEiEvv", "_ZN1N1fE", "_ZN6System5Sound4beepEv", "_ZN5Arena5levelE",
    "_ZN5StackIiiE5levelE", "_Z1fI1XEvPVN1AIT_E1TE", "_Z4makeI7FactoryiET_IT0_Ev",
    "_Z3foo5Hello5WorldS0_S_", "_Z3fooPM2ABi", "_ZlsRSoRKSs", "_ZTI7a_class",
    "_ZZN1A3fooEiE1B", "_ZZ1fvEN1C1DE",
    # --- local names --------------------------------------------------
    "_ZZN1S1fEiE1g", "_ZZ1fvE1x", "_ZZ1fvEs",
    # --- constructors / destructors ----------------------------------
    "_ZN1AC1Ev", "_ZN1AC2Ev", "_ZN1AC3Ev", "_ZN1AD0Ev", "_ZN1AD1Ev", "_ZN1AD2Ev",
    "_ZN7android7IBinderD2Ev", "_ZN7android7IBinderC1Ev",
    # --- operators ----------------------------------------------------
    "_Znwm", "_Znam", "_ZdlPv", "_ZdaPv", "_ZplRK1XS1_", "_ZlsPKc", "_ZrsRi",
    "_ZN1SplE1T", "_ZN1SngEv", "_ZN1ScoEv", "_ZN1SdeEv", "_ZN1SadEv",
    "_ZN1SaSEi", "_ZN1SltEi", "_ZN1SeqEi", "_ZN1SclEv", "_ZN1SixEi",
    "_ZN1ScvRSs",
    # --- libstdc++ real symbols ---------------------------------------
    "_ZNSt6vectorIiSaIiEE9push_backERKi", "_ZNSt6vectorIiSaIiEE9push_backEOi",
    "_ZNSt6vectorIiSaIiEEixEm", "_ZSt6vectorIiSaIiEE", "_ZNSs6appendEPKc",
    "_ZNSsC1EPKcRKSs", "_ZNSolsEi", "_ZNSolsEd", "_ZNSolsEPKc", "_ZNSolsEm",
    "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendEPKc",
    "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_",
    "_ZNSt6vectorIiSaIiEEaSERKS1_", "_ZNSt6vectorIiSaIiEE5clearEv",
    "_ZNSt6vectorIiSaIiEE4sizeEv", "_ZNSt6vectorIiSaIiEE5beginEv",
    "_ZNSt6vectorIiSaIiEE3endEv", "_ZNSt6vectorIiSaIiEE5emptyEv",
    "_ZNSt6vectorIiSaIiEEpLEi", "_ZNSaIiEC1Ev", "_ZNSaIiED1Ev", "_ZNSaIiE8allocateEm",
    "_ZNSt11char_traitsIcE6lengthEPKc", "_ZNSt11char_traitsIcE4copyEPcPKcm",
    "_ZSt21__glibcxx_assert_failPKciS0_S0_",
    "_ZNSt8_Rb_treeIiSt4pairIKiSsESt10_Select1stIS2_ESt4lessIiESaIS2_EE16_M_insert_uniqueIS0_EENS2_15_Insert_returnsIS2_EEOT_",
    "_ZNSt3mapIiSsSt4lessIiESaISt4pairIKiSsEEED1Ev",
    "_ZNSt6vectorIS_IiSaIiEESaIS1_EE9push_backEOS1_",
    "_ZNSt6vectorIiSaIiEE15_M_erase_at_endEPi",
    # --- libc++ / Android NDK style ------------------------------------
    "_ZNSt3__16vectorIiNS_9allocatorIiEEE9push_backEOi",
    "_ZNSt3__16vectorIiNS_9allocatorIiEEEixEm",
    "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc",
    # --- special names -------------------------------------------------
    "_ZTV1S", "_ZTI1S", "_ZTS1S", "_ZTT1S", "_ZGV1S", "_ZGR1S_",
    "_ZThn8_N1S1fEv", "_ZTv0_n24_N1S1fEv",
    # --- exotic but real ------------------------------------------------
    "_Z1fPFivE", "_Z1fM1AFivE", "_Z1fA100_i", "_Z1fiz", "_Z1fVKsPFivEM1AFivE",
    "_ZN1SIiE1fIiEEvT_", "_Z1fIiEvPKc", "_Z1fIiEvRKi",
    "_ZNK1S1fEv", "_ZNO1S1fEv", "_ZNR1S1fEv",
    # --- forms recovered from real shared libraries ----------------------
    # A resolved template parameter is itself a substitution candidate.
    "_Z1fI1AEvT_S1_", "_Z1fIPKiEvT_S2_",
    # Constructor templates (explicit arguments, dropped return type).
    "_ZN1A1BC2IiEEvT_", "_ZN1A1BC2IiEEiT_", "_ZN1A1BC2IiEET_",
    "_ZN1AIiE1BC2IiEEvS2_",
    "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC2IPKcvEET_S8_RKS3_",
    "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1IN9__gnu_cxx17__normal_iteratorIPcS4_EEvEET_SA_RKS3_",
    # Free function and member templates.
    "_ZStplIcSt11char_traitsIcESaIcEENSt7__cxx1112basic_stringIT_T0_T1_EERKS8_SA_",
    "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIN9__gnu_cxx17__normal_iteratorIPcS4_EEEEvT_SA_St20forward_iterator_tag",
    # Transactional-memory clone.
    "_ZGTtNSt11logic_errorD1Ev",
    # Deeply nested templates from libproj (duplicate-prefix substitution).
    "_ZN5osgeo4proj9operation14Transformation20createVerticalOffsetERKNS0_4util11PropertyMapERKN7dropbox6oxygen2nnISt10shared_ptrINS0_3crs3CRSEEEESG_RKNS0_6common6LengthERKSt6vectorINS9_ISA_INS0_8metadata18PositionalAccuracyEEEESaISP_EE",
    "_ZThn24_N5osgeo4proj9operation18OperationParameterD0Ev",
    # --- C and JNI exports ----------------------------------------------
    "Java_com_example_Foo_nativeInit",
    "Java_com_example_Foo_nativeInit__ILjava_lang_String_2",
    "Java_com_example_My_1Class_do_1work__I_3I",
    "main", "JNI_OnLoad", "registerNatives", "_init", "_fini",
]


def _normalize(text: str) -> str:
    """Collapse cosmetic differences between the two demanglers.

    Both implementations now emit the reference ``"<a, b >"`` spacing, so only
    whitespace runs and the special-name display formats need aligning.
    """
    text = re.sub(r"\s+>", ">", text)
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"^\{vtable\((.+)\)\}$", r"vtable for \1", text)
    text = re.sub(r"^\{vtt\((.+)\)\}$", r"VTT for \1", text)
    text = re.sub(
        r"^\{virtual override thunk\(\{offset\((-?\d+)\)\}, (.+)\)\}$",
        r"virtual thunk to \2 (\1)",
        text,
    )
    text = re.sub(
        r"^\{virtual override thunk\(\{virtual offset\((-?\d+), (-?\d+)\)\}, (.+)\)\}$",
        r"virtual thunk to \3 (\2)",
        text,
    )
    text = re.sub(r"^reference temporary #\d+ for ", "reference temporary for ", text)
    return text


def _oracle(name: str) -> str | None:
    try:
        return _normalize(cpp_demangle.demangle(name))
    except Exception:
        return None


@pytest.mark.parametrize("mangled", CORPUS, ids=CORPUS)
def test_demangle_matches_reference_implementation(mangled):
    expected = _oracle(mangled)
    if expected is None:
        pytest.skip(f"{mangled} is not well-formed for the reference demangler")

    assert _normalize(demangle(mangled).display) == expected
