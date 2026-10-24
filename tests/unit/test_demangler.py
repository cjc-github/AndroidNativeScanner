"""Unit tests for the Itanium C++ ABI demangler."""

import pytest

from soinsight.infrastructure.elf import demangle

# Vectors from the Itanium C++ ABI examples document plus real-world
# libstdc++/libc++/Android NDK symbols. The full set is cross-checked against
# the cpp_demangle oracle by scripts/compare_demangle.py.
VECTORS = [
    # --- names and scopes ---------------------------------------------
    ("_Z1fv", "f()", "function"),
    ("_Z1fi", "f(int)", "function"),
    ("_Z3foo3bar", "foo(bar)", "function"),
    ("_ZN1N1fE", "N::f", "data"),
    ("_ZN6System5Sound4beepEv", "System::Sound::beep()", "method"),
    ("_ZN5Arena5levelE", "Arena::level", "data"),
    ("_ZN5StackIiiE5levelE", "Stack<int, int>::level", "data"),
    # --- templates -----------------------------------------------------
    ("_Z1fIiEvi", "void f<int>(int)", "function"),
    ("_Z1fIiEvT_", "void f<int>(int)", "function"),
    ("_ZN1S1fIiEEvT_", "void S::f<int>(int)", "method"),
    ("_ZN1SIiE1fEv", "S<int>::f()", "method"),
    ("_Z4makeI7FactoryiET_IT0_Ev", "Factory<int> make<Factory, int>()", "function"),
    ("_ZN3FooIA4_iE3barE", "Foo<int [4]>::bar", "data"),
    # --- substitutions --------------------------------------------------
    ("_Z3foo5Hello5WorldS0_S_", "foo(Hello, World, World, Hello)", "function"),
    ("_ZplR1XS0_", "operator+(X&, X&)", "operator"),
    ("_ZlsRK1XS1_", "operator<<(X const&, X const&)", "operator"),
    ("_ZNSt6vectorIiSaIiEE9push_backERKi",
     "std::vector<int, std::allocator<int> >::push_back(int const&)", "method"),
    ("_ZNSt6vectorIS_IiSaIiEESaIS1_EE9push_backEOS1_",
     "std::vector<std::vector<int, std::allocator<int> >, "
     "std::allocator<std::vector<int, std::allocator<int> > > >::push_back("
     "std::vector<int, std::allocator<int> >&&)", "method"),
    # --- operators ------------------------------------------------------
    ("_Zrm1XS_", "operator%(X, X)", "operator"),
    ("_Znwm", "operator new(unsigned long)", "operator"),
    ("_Znam", "operator new[](unsigned long)", "operator"),
    ("_ZdlPv", "operator delete(void*)", "operator"),
    ("_ZdaPv", "operator delete[](void*)", "operator"),
    ("_ZNSolsEi", "std::ostream::operator<<(int)", "operator"),
    ("_ZNSt6vectorIiSaIiEEixEm",
     "std::vector<int, std::allocator<int> >::operator[](unsigned long)", "operator"),
    # --- constructors and destructors -----------------------------------
    ("_ZN1AC1Ev", "A::A()", "constructor"),
    ("_ZN1AC2Ev", "A::A()", "constructor"),
    ("_ZN1AC3Ev", "A::A()", "constructor"),
    ("_ZN1AD0Ev", "A::~A()", "destructor"),
    ("_ZN1AD1Ev", "A::~A()", "destructor"),
    ("_ZN1AD2Ev", "A::~A()", "destructor"),
    ("_ZNSaIiEC1Ev", "std::allocator<int>::allocator()", "constructor"),
    ("_ZNSaIiED1Ev", "std::allocator<int>::~allocator()", "destructor"),
    ("_ZN7android7IBinderD2Ev", "android::IBinder::~IBinder()", "destructor"),
    # --- member function qualifiers --------------------------------------
    ("_ZNK1S1fEv", "S::f() const", "method"),
    ("_ZNO1S1fEv", "S::f() &&", "method"),
    ("_ZNR1S1fEv", "S::f() &", "method"),
    # --- compound types ---------------------------------------------------
    ("_Z1fPFivE", "f(int (*)())", "function"),
    ("_Z1fM1AFivE", "f(int (A::*)())", "function"),
    ("_Z1fA100_i", "f(int [100])", "function"),
    ("_Z1fiz", "f(int, ...)", "function"),
    ("_Z1fVKsPFivEM1AFivE", "f(short const volatile, int (*)(), int (A::*)())", "function"),
    ("_Z1fI1XEvPVN1AIT_E1TE", "void f<X>(A<X>::T volatile*)", "function"),
    ("_Z3fooIiPFidEiEvv", "void foo<int, int (*)(double), int>()", "function"),
    # A substitution reused as the prefix of a nested name inside a parameter.
    ("_ZN2ns5Class6methodEiRKNS_4TypeE", "ns::Class::method(int, ns::Type const&)", "method"),
    # --- local names -------------------------------------------------------
    ("_ZZN1S1fEiE1g", "S::f(int)::g", "data"),
    ("_ZZ1fvE1x", "f()::x", "data"),
    ("_ZZN1A3fooEiE1B", "A::foo(int)::B", "data"),
    ("_ZZ1fvEN1C1DE", "f()::C::D", "data"),
    # --- special names -------------------------------------------------------
    ("_ZTV1S", "vtable for S", "special"),
    ("_ZTI1S", "typeinfo for S", "special"),
    ("_ZTS1S", "typeinfo name for S", "special"),
    ("_ZTT1S", "VTT for S", "special"),
    ("_ZGV1S", "guard variable for S", "special"),
    ("_ZGR1S_", "reference temporary for S", "special"),
    ("_ZThn8_N1S1fEv", "virtual thunk to S::f() (-8)", "special"),
    ("_ZTv0_n24_N1S1fEv", "virtual thunk to S::f() (-24)", "special"),
    # --- standard substitutions ------------------------------------------------
    ("_ZlsRSoRKSs", "operator<<(std::ostream&, std::string const&)", "operator"),
    ("_ZNSs6appendEPKc", "std::string::append(char const*)", "method"),
    ("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendEPKc",
     "std::__cxx11::basic_string<char, std::char_traits<char>, "
     "std::allocator<char> >::append(char const*)", "method"),
    ("_ZNSt3__16vectorIiNS_9allocatorIiEEE9push_backEOi",
     "std::__1::vector<int, std::__1::allocator<int> >::push_back(int&&)", "method"),
    # --- cases recovered from real shared libraries ---------------------------
    # A resolved template parameter is itself a substitution candidate, so the
    # same type can occupy two indices.
    ("_Z1fI1AEvT_S1_", "void f<A>(A, A)", "function"),
    ("_Z1fIPKiEvT_S2_", "void f<int const*>(int const*, int const*)", "function"),
    # Constructor templates: explicit arguments are kept, the return type the
    # ABI still encodes is dropped, and the prefix uses the class name.
    ("_ZN1A1BC2IiEEvT_", "A::B::B<int>(int)", "constructor"),
    ("_ZN1A1BC2IiEEiT_", "A::B::B<int>(int)", "constructor"),
    ("_ZN1A1BC2IiEET_", "A::B::B<int>()", "constructor"),
    ("_ZN1AIiE1BC2IiEEvS2_", "A<int>::B::B<int>(A<int>::B::B)", "constructor"),
    # A name whose template arguments contain "::" must not be split there.
    ("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1IN9__gnu_cxx17__normal_iteratorIPcS4_EEvEET_SA_RKS3_",
     "std::__cxx11::basic_string<char, std::char_traits<char>, "
     "std::allocator<char> >::basic_string<__gnu_cxx::__normal_iterator<char*, "
     "std::__cxx11::basic_string<char, std::char_traits<char>, "
     "std::allocator<char> > >, void>(__gnu_cxx::__normal_iterator<char*, "
     "std::__cxx11::basic_string<char, std::char_traits<char>, "
     "std::allocator<char> > >, std::allocator<char> const&)", "constructor"),
    ("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC2IPKcvEET_S8_RKS3_",
     "std::__cxx11::basic_string<char, std::char_traits<char>, "
     "std::allocator<char> >::basic_string<char const*, void>(char const*, "
     "std::allocator<char> const&)", "constructor"),
    # Free function template in a namespace with a template-dependent return.
    ("_ZStplIcSt11char_traitsIcESaIcEENSt7__cxx1112basic_stringIT_T0_T1_EERKS8_SA_",
     "std::__cxx11::basic_string<char, std::char_traits<char>, "
     "std::allocator<char> > std::operator+<char, std::char_traits<char>, "
     "std::allocator<char> >(std::__cxx11::basic_string<char, "
     "std::char_traits<char>, std::allocator<char> > const&, "
     "std::__cxx11::basic_string<char, std::char_traits<char>, "
     "std::allocator<char> > const&)", "operator"),
    # Member template whose argument is itself a template-id.
    ("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIN9__gnu_cxx17__normal_iteratorIPcS4_EEEEvT_SA_St20forward_iterator_tag",
     "void std::__cxx11::basic_string<char, std::char_traits<char>, "
     "std::allocator<char> >::_M_construct<__gnu_cxx::__normal_iterator<char*, "
     "std::__cxx11::basic_string<char, std::char_traits<char>, "
     "std::allocator<char> > > >(__gnu_cxx::__normal_iterator<char*, "
     "std::__cxx11::basic_string<char, std::char_traits<char>, "
     "std::allocator<char> > >, __gnu_cxx::__normal_iterator<char*, "
     "std::__cxx11::basic_string<char, std::char_traits<char>, "
     "std::allocator<char> > >, std::forward_iterator_tag)", "method"),
    # Transactional-memory clone.
    ("_ZGTtNSt11logic_errorD1Ev",
     "transaction clone for std::logic_error::~logic_error()", "special"),
    # --- D-prefixed builtin types --------------------------------------------
    # These are matched before the decltype dispatch, so "Ds" never reaches the
    # D-form parser that only understands Dt/DT/Dp/Dv.
    ("_Z1fDs", "f(char16_t)", "function"),
    ("_Z1fDi", "f(char32_t)", "function"),
    ("_Z1fDu", "f(char8_t)", "function"),
    ("_Z1fDn", "f(decltype(nullptr))", "function"),
    ("_ZSt6vectorIDsSaIDsEE3fooEv",
     "foo std::vector<char16_t, std::allocator<char16_t> >()", "method"),
    ("_ZN9QXmlUtils6isCharEDi", "QXmlUtils::isChar(char32_t)", "method"),
    # Half precision: "Dh" is the NDK libc++ spelling, "DF" the ABI code.
    ("_Z1fDh", "f(half)", "function"),
    ("_Z1fDF", "f(half)", "function"),
    # --- increment/decrement/arrow operators ---------------------------------
    ("_ZN19QSequentialIterable14const_iteratorppEv",
     "QSequentialIterable::const_iterator::operator++()", "operator"),
    ("_ZN19QSequentialIterable14const_iteratormmEi",
     "QSequentialIterable::const_iterator::operator--(int)", "operator"),
    ("_ZN22QAndroidJniEnvironmentptEv",
     "QAndroidJniEnvironment::operator->()", "operator"),
    # --- conversion operators carry no written return type -------------------
    ("_ZNK22QAndroidJniEnvironmentcvP7_JNIEnvEv",
     "QAndroidJniEnvironment::operator _JNIEnv*() const", "operator"),
    ("_ZNK7QPixmapcv8QVariantEv", "QPixmap::operator QVariant() const", "operator"),
    # --- construction vtables and typeinfo on D-types ------------------------
    ("_ZTCNSt6__ndk114basic_iostreamIcNS_11char_traitsIcEEEE0_NS_13basic_istreamIcS2_EE",
     "construction vtable for std::__ndk1::basic_iostream<char, "
     "std::__ndk1::char_traits<char> >-in-std::__ndk1::basic_istream<char, "
     "std::__ndk1::char_traits<char> >", "special"),
    ("_ZTIDh", "typeinfo for half", "special"),
    ("_ZTIPDh", "typeinfo for half*", "special"),
    # --- expressions inside template arguments -------------------------------
    # "sr" starts an unresolved name (Type::member), not the ->* operator.
    ("_Z1fIXsr12QMetaTypeId2IS_EE7DefinedEEvv",
     "void f<QMetaTypeId2<f>::Defined>()", "method"),
    # A bool literal is spelled as the source wrote it, not as 0/1. These name
    # a template instantiation with no parameter list, so they classify as data
    # (the same rule that makes "Stack<int, int>::level" data).
    ("_Z1fILb1EEEvv", "f<true>", "data"),
    ("_Z1fILb0EEEvv", "f<false>", "data"),
    ("_ZNKSt6__ndk115__codecvt_utf16IDsLb1EE13do_max_lengthEv",
     "std::__ndk1::__codecvt_utf16<char16_t, true>::do_max_length() const",
     "method"),
    # Logical operators and nested unresolved names, as Qt's qRegisterMetaType
    # emits for its MetaTypeDefinedHelper trait.
    ("_Z17qRegisterMetaTypeI7QStringEiPKcPT_N9QtPrivate21MetaTypeDefinedHelperIS2_Xaasr12QMetaTypeId2IS2_EE7Definedntsr12QMetaTypeId2IS2_EE9IsBuiltInEE11DefinedTypeE",
     "int qRegisterMetaType<QString>(char const*, QString*, "
     "QtPrivate::MetaTypeDefinedHelper<char const*, "
     "(QMetaTypeId2<char const*>::Defined && !(QMetaTypeId2<char const*>::IsBuiltIn))"
     ">::DefinedType)", "function"),
    # --- lambdas take a parameter list, not a single type --------------------
    ("_ZZZNK18QFileDialogPrivate8rootPathEvENKUlvE_clEvE15qstring_literal",
     "QFileDialogPrivate::rootPath() const::{lambda(void)#1}::operator()()::"
     "qstring_literal", "data"),
]


@pytest.mark.parametrize(
    "mangled,expected_display,expected_kind",
    VECTORS,
    ids=[vector[0] for vector in VECTORS],
)
def test_demangle_matches_expected(mangled, expected_display, expected_kind):
    result = demangle(mangled)

    assert result.display == expected_display
    assert result.kind == expected_kind


def test_demangle_recovers_parameter_types():
    result = demangle("_ZNSt6vectorIiSaIiEE9push_backERKi")

    assert result.parameters == ("int const&",)
    assert result.return_type is None
    assert result.namespace == "std::vector<int, std::allocator<int> >"
    assert result.short_name == "push_back"


def test_demangle_reports_return_type_only_for_templates():
    assert demangle("_Z1fIiEvi").return_type == "void"
    assert demangle("_Z1fi").return_type is None
    assert demangle("_ZNSt6vectorIiSaIiEE9push_backERKi").return_type is None


def test_demangle_marks_c_names_as_unmangled():
    result = demangle("Java_com_example_Foo_nativeInit")

    assert result.kind == "unmangled"
    assert result.language == "c"
    assert result.display == "Java_com_example_Foo_nativeInit"


@pytest.mark.parametrize(
    "mangled",
    [
        "_ZN1A1B",                # unterminated nested name
        "_ZN1A1BEF",              # trailing garbage after a data name
        "_Z1fS9_",                # substitution index out of range
        "_Z1fQ",                  # unsupported type code
        "_ZTs",                   # incomplete special name
        "_Z1fI1XEvT9_",           # template parameter index out of range
    ],
)
def test_demangle_never_raises_on_malformed_input(mangled):
    """Undecodable names fall back to the raw text instead of guessing."""
    result = demangle(mangled)

    assert result.kind == "undecoded"
    assert result.display == mangled


def test_demangle_tolerates_empty_and_whitespace_input():
    assert demangle("").kind == "unmangled"
    assert demangle("   ").kind == "unmangled"
