"""Static cross-reference extraction over decoded machine code.

The module re-decodes a code region with Capstone's *detail* mode enabled and
resolves the absolute address every instruction points at. The result is
architecture specific, but the interface is uniform: a tuple of
:class:`CodeReference` records that the analyzer layer matches against a
table of interesting addresses (string literals, function entry points, ...).

Supported reference kinds per architecture:

``x86`` / ``x86-64``
    ``rip-relative`` (RIP-relative memory operands), ``absolute`` (absolute
    memory operands) and ``immediate`` (constant operands).
``aarch64``
    ``adr`` (PC-relative literal), ``adrp-add`` (page materialised by
    ``adrp``/``add`` pairs), ``register-load`` (memory operand whose base
    register holds a tracked address) and ``branch``.
``arm``
    ``literal`` (a PC-relative literal-pool load folded into ``add rd, pc, rn``)
    and ``register-load`` (a memory operand whose base register is tracked,
    including the value assembled by ``movw``/``movt`` half immediates).

Register tracking is local to one decoded blob and does not model control flow.
A tracked value is dropped as soon as the register is written by an instruction
the page arithmetic does not recognise, and a call drops every register the
ABI lets the callee clobber: keeping a stale page would report references to
addresses the load does not point at. Flag-setting forms are excluded from
invalidation because this Capstone build marks their register source operand as
written while only NZCV changes. Pre/post-index write-back on AArch64 is not
modelled (the operand carries no ``writeback`` member in this build), so a page
tracked in a register that is also a write-back base can survive one load; a
missed reference is preferred over a guessed one.
"""

from dataclasses import dataclass

from .disasm import capstone_module

__all__ = ["CodeReference", "decode_references"]


@dataclass(frozen=True)
class CodeReference:
    """One absolute address referenced by a single instruction."""

    address: int
    """Virtual address of the referencing instruction."""

    target: int
    """Absolute address the instruction points at."""

    kind: str
    """How the reference was recovered (``rip-relative``, ``adrp-add``, ...)."""


# Registers a call may clobber: x0-x18 for AAPCS64, r0-r3 and r12 for AAPCS.
# The stack and frame pointers are callee-saved, so a page held in them (or in
# x19-x28 / r4-r11) survives a call.
_A64_CALLER_SAVED = frozenset(f"g{index}" for index in range(19))
_ARM_CALLER_SAVED = frozenset({"g0", "g1", "g2", "g3", "g12"})

# AArch64 forms whose register operand this build marks as written although the
# instruction only updates NZCV: invalidating on them would drop live pages.
_A64_FLAG_ONLY = frozenset({"cmp", "cmn", "tst", "teq"})


def _register_key(engine, reg: int) -> str | None:
    """Fold an architectural register to a key shared by its aliases.

    ``w0`` and ``x0`` name one hardware register, so a write through the narrow
    alias must invalidate a page tracked under the wide name. An integer
    register reduces to its number; anything else (stack pointer, link register,
    flags, vector and SVE registers) keeps its own name, and register id 0 --
    meaning "no register" -- maps to ``None``.
    """
    if not reg:
        return None
    name = engine.reg_name(reg)
    if name and len(name) > 1 and name[0] in ("x", "w", "r") and name[1:].isdigit():
        return "g" + name[1:]
    return name


def _written_keys(engine, operands, reg_constant, write_bit: int) -> set:
    """Return the registers an instruction writes through a *register* operand.

    Memory operands are deliberately not consulted: their access bits mix in
    base-register write-back and store semantics that the tracking does not
    model here.
    """
    keys = set()
    for operand in operands:
        if operand.type != reg_constant or not operand.access & write_bit:
            continue
        key = _register_key(engine, operand.reg)
        if key is not None:
            keys.add(key)
    return keys


def decode_references(
    blob: bytes,
    start_address: int,
    arch: int,
    mode: int,
) -> tuple[CodeReference, ...]:
    """Decode ``blob`` and return every absolute address it references."""
    module = capstone_module()
    if module is None:
        return ()
    engine = module.Cs(arch, mode)
    engine.detail = True
    if arch == module.CS_ARCH_X86:
        references = _x86_references(engine, blob, start_address)
    elif arch == module.CS_ARCH_ARM64:
        references = _arm64_references(engine, blob, start_address, module)
    elif arch == module.CS_ARCH_ARM:
        references = _arm_references(engine, blob, start_address, module)
    else:
        return ()
    return tuple(references)


def _x86_references(engine, blob: bytes, start_address: int) -> list[CodeReference]:
    """Resolve x86 and x86-64 memory and immediate operands.

    No register tracking is needed: a RIP-relative operand carries its full
    displacement, so there is no derived value that could go stale.
    """
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

    references: list[CodeReference] = []
    for insn in engine.disasm(blob, start_address):
        branch = _is_x86_branch(insn.mnemonic)
        for operand in insn.operands:
            if operand.type == X86_OP_MEM:
                if operand.mem.base == X86_REG_RIP:
                    target = insn.address + insn.size + operand.mem.disp
                    references.append(
                        CodeReference(insn.address, target, "rip-relative")
                    )
                elif operand.mem.base == 0 and operand.mem.index == 0:
                    references.append(
                        CodeReference(insn.address, operand.mem.disp, "absolute")
                    )
            elif operand.type == X86_OP_IMM:
                # A branch operand points at code, not at data.
                kind = "branch" if branch else "immediate"
                references.append(CodeReference(insn.address, operand.imm, kind))
    return references


def _is_x86_branch(mnemonic: str) -> bool:
    """Tell whether an x86 mnemonic transfers control to an immediate target."""
    return mnemonic.startswith("call") or mnemonic.startswith("j") or mnemonic.startswith(
        "loop"
    )


def _arm64_references(
    engine, blob: bytes, start_address: int, module
) -> list[CodeReference]:
    """Resolve AArch64 addresses, tracking the register that holds one.

    The page materialised by ``adrp``/``adr`` is followed through ``add``/``sub``
    immediates and register-to-register moves; any other write to the holding
    register drops it, as does a call that clobbers it.
    """
    from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

    references: list[CodeReference] = []
    tracked: dict[str, int] = {}
    for insn in engine.disasm(blob, start_address):
        operands = insn.operands
        mnemonic = insn.mnemonic
        handled = False
        if (
            mnemonic == "adrp"
            and len(operands) >= 2
            and operands[0].type == ARM64_OP_REG
            and operands[1].type == ARM64_OP_IMM
        ):
            # ``adrp`` only materialises a page; the exact address needs the
            # matching ``add``, so the page itself is not reported.
            key = _register_key(engine, operands[0].reg)
            if key is not None:
                tracked[key] = operands[1].imm
            handled = True
        elif (
            mnemonic == "adr"
            and len(operands) >= 2
            and operands[0].type == ARM64_OP_REG
            and operands[1].type == ARM64_OP_IMM
        ):
            key = _register_key(engine, operands[0].reg)
            if key is not None:
                tracked[key] = operands[1].imm
            references.append(
                CodeReference(insn.address, operands[1].imm, "adr")
            )
            handled = True
        elif (
            mnemonic in ("add", "sub")
            and len(operands) == 3
            and operands[0].type == ARM64_OP_REG
            and operands[1].type == ARM64_OP_REG
            and operands[2].type == ARM64_OP_IMM
        ):
            key = _register_key(engine, operands[0].reg)
            source = _register_key(engine, operands[1].reg)
            base = tracked.get(source) if source is not None else None
            if base is not None:
                delta = operands[2].imm if mnemonic == "add" else -operands[2].imm
                value = base + delta
                if key is not None:
                    tracked[key] = value
                references.append(
                    CodeReference(insn.address, value, "adrp-add")
                )
            elif key is not None:
                # The destination is overwritten from an untracked register:
                # whatever page it used to hold is gone.
                tracked.pop(key, None)
            handled = True
        elif (
            mnemonic == "mov"
            and len(operands) == 2
            and operands[0].type == ARM64_OP_REG
            and operands[1].type == ARM64_OP_REG
        ):
            source = _register_key(engine, operands[1].reg)
            key = _register_key(engine, operands[0].reg)
            if key is not None:
                value = tracked.get(source) if source is not None else None
                if value is None:
                    tracked.pop(key, None)
                else:
                    tracked[key] = value
            handled = True
        if not handled and mnemonic not in _A64_FLAG_ONLY:
            for key in _written_keys(
                engine, operands, ARM64_OP_REG, module.CS_AC_WRITE
            ):
                tracked.pop(key, None)
        if mnemonic in ("bl", "blr", "br"):
            for key in _A64_CALLER_SAVED:
                tracked.pop(key, None)
        for operand in operands:
            if operand.type == ARM64_OP_MEM:
                base = tracked.get(_register_key(engine, operand.mem.base))
                if base is not None:
                    references.append(
                        CodeReference(
                            insn.address,
                            base + operand.mem.disp,
                            "register-load",
                        )
                    )
        if (
            mnemonic.startswith("b")
            and len(operands) >= 1
            and operands[0].type == ARM64_OP_IMM
        ):
            references.append(
                CodeReference(insn.address, operands[0].imm, "branch")
            )
    return references


def _arm_references(
    engine, blob: bytes, start_address: int, module
) -> list[CodeReference]:
    """Resolve ARM (A32) addresses, tracking registers and literal pools."""
    from capstone.arm_const import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

    references: list[CodeReference] = []
    tracked: dict[str, int] = {}
    for insn in engine.disasm(blob, start_address):
        operands = insn.operands
        mnemonic = insn.mnemonic
        handled = False
        if (
            mnemonic == "movw"
            and len(operands) >= 2
            and operands[0].type == ARM_OP_REG
            and operands[1].type == ARM_OP_IMM
        ):
            key = _register_key(engine, operands[0].reg)
            if key is not None:
                # ``movw`` is a MOVZ: it clears the upper half, so the fresh
                # value never merges with a previous one.
                tracked[key] = operands[1].imm
            handled = True
        elif (
            mnemonic == "movt"
            and len(operands) >= 2
            and operands[0].type == ARM_OP_REG
            and operands[1].type == ARM_OP_IMM
        ):
            key = _register_key(engine, operands[0].reg)
            previous = tracked.get(key) if key is not None else None
            if previous is None:
                # Upper half alone does not identify an address; a stale
                # half-tracked value is worse than none.
                if key is not None:
                    tracked.pop(key, None)
            elif key is not None:
                tracked[key] = (previous & 0x0000FFFF) | (operands[1].imm << 16)
            handled = True
        elif (
            mnemonic == "ldr"
            and len(operands) >= 2
            and operands[0].type == ARM_OP_REG
            and operands[1].type == ARM_OP_MEM
            and operands[1].mem.base == ARM_REG_PC
        ):
            literal = _literal_word(
                blob, start_address, insn.address, operands[1].mem.disp
            )
            key = _register_key(engine, operands[0].reg)
            if key is not None:
                if literal is None:
                    tracked.pop(key, None)
                else:
                    tracked[key] = literal
            handled = True
        elif (
            mnemonic == "add"
            and len(operands) == 3
            and operands[0].type == ARM_OP_REG
            and operands[1].type == ARM_OP_REG
            and operands[2].type == ARM_OP_REG
            and operands[1].reg == ARM_REG_PC
        ):
            key = _register_key(engine, operands[0].reg)
            loaded = tracked.get(_register_key(engine, operands[2].reg))
            if loaded is not None:
                value = (insn.address + 8 + loaded) & 0xFFFFFFFF
                if key is not None:
                    tracked[key] = value
                references.append(
                    CodeReference(insn.address, value, "literal")
                )
            elif key is not None:
                tracked.pop(key, None)
            handled = True
        elif (
            mnemonic == "add"
            and len(operands) == 3
            and operands[0].type == ARM_OP_REG
            and operands[1].type == ARM_OP_REG
            and operands[2].type == ARM_OP_IMM
        ):
            key = _register_key(engine, operands[0].reg)
            base = tracked.get(_register_key(engine, operands[1].reg))
            if base is not None and key is not None:
                tracked[key] = (base + operands[2].imm) & 0xFFFFFFFF
            elif key is not None:
                tracked.pop(key, None)
            handled = True
        elif (
            mnemonic == "mov"
            and len(operands) == 2
            and operands[0].type == ARM_OP_REG
            and operands[1].type == ARM_OP_REG
        ):
            source = _register_key(engine, operands[1].reg)
            key = _register_key(engine, operands[0].reg)
            if key is not None:
                value = tracked.get(source) if source is not None else None
                if value is None:
                    tracked.pop(key, None)
                else:
                    tracked[key] = value
            handled = True
        if not handled:
            for key in _written_keys(
                engine, operands, ARM_OP_REG, module.CS_AC_WRITE
            ):
                tracked.pop(key, None)
        if mnemonic in ("bl", "blx", "bx"):
            for key in _ARM_CALLER_SAVED:
                tracked.pop(key, None)
        for operand in operands:
            if operand.type == ARM_OP_MEM:
                base = tracked.get(_register_key(engine, operand.mem.base))
                if base is not None:
                    references.append(
                        CodeReference(
                            insn.address,
                            base + operand.mem.disp,
                            "register-load",
                        )
                    )
    return references


def _literal_word(
    blob: bytes, start_address: int, pc: int, displacement: int
) -> int | None:
    """Read the 32-bit literal pool word addressed by ``[pc, #displacement]``."""
    literal_address = (pc + 8 + displacement) & ~0x3
    offset = literal_address - start_address
    if offset < 0 or offset + 4 > len(blob):
        return None
    return int.from_bytes(blob[offset : offset + 4], "little")
