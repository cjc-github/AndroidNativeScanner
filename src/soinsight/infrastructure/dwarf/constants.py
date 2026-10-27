"""ELF and DWARF constants needed by the debug-info parser.

Only the subset the parser actually consumes is listed; unknown values are
rendered numerically by the caller rather than guessed at.
"""

# ELF section names holding debug information.
SECTION_DEBUG_INFO = ".debug_info"
SECTION_DEBUG_ABBREV = ".debug_abbrev"
SECTION_DEBUG_STR = ".debug_str"
SECTION_DEBUG_LINE_STR = ".debug_line_str"
SECTION_DEBUG_LINE = ".debug_line"

# DWARF tags.
DW_TAG_array_type = 0x01
DW_TAG_class_type = 0x02
DW_TAG_entry_point = 0x03
DW_TAG_enumeration_type = 0x04
DW_TAG_formal_parameter = 0x05
DW_TAG_imported_declaration = 0x08
DW_TAG_label = 0x0A
DW_TAG_lexical_block = 0x0B
DW_TAG_member = 0x0D
DW_TAG_pointer_type = 0x0F
DW_TAG_reference_type = 0x10
DW_TAG_compile_unit = 0x11
DW_TAG_string_type = 0x12
DW_TAG_structure_type = 0x13
DW_TAG_subroutine_type = 0x15
DW_TAG_typedef = 0x16
DW_TAG_union_type = 0x17
DW_TAG_unspecified_parameters = 0x18
DW_TAG_variant = 0x19
DW_TAG_common_block = 0x1A
DW_TAG_namespace = 0x39
DW_TAG_inheritance = 0x1C
DW_TAG_enumerator = 0x28
DW_TAG_inlined_subroutine = 0x1D
DW_TAG_subprogram = 0x2E
DW_TAG_variable = 0x34
DW_TAG_volatile_type = 0x35
DW_TAG_restrict_type = 0x37
DW_TAG_atomic_type = 0x47
DW_TAG_const_type = 0x38

# Tags whose DW_AT_name qualifies an enclosed function.
_NAMESPACE_TAGS = frozenset(
    {DW_TAG_namespace, DW_TAG_class_type, DW_TAG_structure_type, DW_TAG_union_type}
)

# DWARF attributes.
DW_AT_sibling = 0x01
DW_AT_location = 0x02
DW_AT_name = 0x03
DW_AT_byte_size = 0x0B
DW_AT_stmt_list = 0x10
DW_AT_low_pc = 0x11
DW_AT_high_pc = 0x12
DW_AT_comp_dir = 0x1B
DW_AT_const_value = 0x1C
DW_AT_abstract_origin = 0x31
DW_AT_producer = 0x25
DW_AT_prototyped = 0x27
DW_AT_specification = 0x47
DW_AT_type = 0x49
DW_AT_data_member_location = 0x38
DW_AT_linkage_name = 0x6E
DW_AT_decl_file = 0x58
DW_AT_decl_line = 0x59
DW_AT_ranges = 0x55
DW_AT_accessibility = 0x32
DW_AT_external = 0x3F
DW_AT_virtuality = 0x6B

# DWARF forms.
DW_FORM_addr = 0x01
DW_FORM_block2 = 0x03
DW_FORM_block4 = 0x04
DW_FORM_data2 = 0x05
DW_FORM_data4 = 0x06
DW_FORM_data8 = 0x07
DW_FORM_string = 0x08
DW_FORM_block = 0x09
DW_FORM_block1 = 0x0A
DW_FORM_data1 = 0x0B
DW_FORM_flag = 0x0C
DW_FORM_sdata = 0x0D
DW_FORM_strp = 0x0E
DW_FORM_udata = 0x0F
DW_FORM_ref_addr = 0x10
DW_FORM_ref1 = 0x11
DW_FORM_ref2 = 0x12
DW_FORM_ref4 = 0x13
DW_FORM_ref8 = 0x14
DW_FORM_ref_udata = 0x15
DW_FORM_indirect = 0x16
DW_FORM_sec_offset = 0x17
DW_FORM_exprloc = 0x18
DW_FORM_flag_present = 0x19
DW_FORM_strx = 0x1A
DW_FORM_addrx = 0x1B
DW_FORM_ref_sup4 = 0x1C
DW_FORM_strp_sup = 0x1D
DW_FORM_data16 = 0x1E
DW_FORM_line_strp = 0x1F
DW_FORM_ref_sig8 = 0x20
DW_FORM_implicit_const = 0x21
DW_FORM_loclistx = 0x22
DW_FORM_rnglistx = 0x23
DW_FORM_ref_sup8 = 0x24
DW_FORM_strx1 = 0x25
DW_FORM_strx2 = 0x26
DW_FORM_strx3 = 0x27
DW_FORM_strx4 = 0x28
DW_FORM_addrx1 = 0x29
DW_FORM_addrx2 = 0x2A
DW_FORM_addrx3 = 0x2B
DW_FORM_addrx4 = 0x2C

# DWARF unit types (version 5 and later).
DW_UT_compile = 0x01
DW_UT_type = 0x02
DW_UT_partial = 0x03
DW_UT_skeleton = 0x04
DW_UT_split_compile = 0x05
DW_UT_split_type = 0x06

# Tag names used in diagnostics and debug output.
DW_TAG_NAMES = {
    DW_TAG_array_type: "array_type",
    DW_TAG_class_type: "class_type",
    DW_TAG_compile_unit: "compile_unit",
    DW_TAG_const_type: "const_type",
    DW_TAG_enumeration_type: "enumeration_type",
    DW_TAG_formal_parameter: "formal_parameter",
    DW_TAG_pointer_type: "pointer_type",
    DW_TAG_reference_type: "reference_type",
    DW_TAG_restrict_type: "restrict_type",
    DW_TAG_structure_type: "structure_type",
    DW_TAG_subprogram: "subprogram",
    DW_TAG_subroutine_type: "subroutine_type",
    DW_TAG_typedef: "typedef",
    DW_TAG_union_type: "union_type",
    DW_TAG_variable: "variable",
    DW_TAG_member: "member",
    DW_TAG_inheritance: "inheritance",
    DW_TAG_enumerator: "enumerator",
    DW_TAG_namespace: "namespace",
    DW_TAG_volatile_type: "volatile_type",
}

DW_AT_NAMES = {
    DW_AT_name: "name",
    DW_AT_linkage_name: "linkage_name",
    DW_AT_low_pc: "low_pc",
    DW_AT_high_pc: "high_pc",
    DW_AT_type: "type",
    DW_AT_decl_file: "decl_file",
    DW_AT_decl_line: "decl_line",
    DW_AT_abstract_origin: "abstract_origin",
    DW_AT_specification: "specification",
    DW_AT_comp_dir: "comp_dir",
    DW_AT_stmt_list: "stmt_list",
    DW_AT_byte_size: "byte_size",
    DW_AT_accessibility: "accessibility",
    DW_AT_external: "external",
    DW_AT_virtuality: "virtuality",
    DW_AT_data_member_location: "data_member_location",
    DW_AT_const_value: "const_value",
}
