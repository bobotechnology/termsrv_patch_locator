# -*- coding: utf-8 -*-
"""Pure instruction-pattern matching used by the IDA plugin.

The matchers mirror llccd/RDPWrapOffsetFinder's x86/x64 Patch.cpp logic while
remaining independent from IDA, which makes the behavior unit-testable.
"""

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class Operand:
    kind: str
    reg: Optional[str] = None
    base: Optional[str] = None
    displacement: Optional[int] = None
    value: Optional[int] = None
    target: Optional[int] = None


@dataclass(frozen=True)
class Instruction:
    ea: int
    size: int
    mnemonic: str
    operands: Tuple[Operand, ...] = ()

    def operand(self, index: int) -> Operand:
        if index < len(self.operands):
            return self.operands[index]
        return Operand("void")


@dataclass(frozen=True)
class PatchMatch:
    name: str
    offset: int
    code: str

    def ini_lines(self, arch: str) -> List[str]:
        return [
            f"{self.name}Patch.{arch}=1",
            f"{self.name}Offset.{arch}={self.offset:X}",
            f"{self.name}Code.{arch}={self.code}",
        ]


def _is_memory(op: Operand, displacement: Optional[int] = None) -> bool:
    return op.kind == "mem" and (displacement is None or op.displacement == displacement)


def _is_register(op: Operand) -> bool:
    return op.kind == "reg" and op.reg is not None


def locate_single_user(
    instructions: Sequence[Instruction],
    arch: str,
    image_base: int,
    memset_target: int,
    verify_version_target: Optional[int],
) -> Optional[PatchMatch]:
    """Locate SingleUser using the post-memset scan from Patch.cpp."""
    for index, insn in enumerate(instructions):
        if insn.mnemonic != "call" or insn.operand(0).target != memset_target:
            continue

        for candidate in instructions[index + 1 :]:
            op0 = candidate.operand(0)
            op1 = candidate.operand(1)

            if (
                verify_version_target is not None
                and candidate.mnemonic == "call"
                and 5 <= candidate.size <= 7
                and op0.target == verify_version_target
            ):
                if arch == "x64":
                    code = f"mov_eax_1_nop_{candidate.size - 5}"
                else:
                    code = f"pop_eax_add_esp_12_nop_{candidate.size - 4}"
                return PatchMatch("SingleUser", candidate.ea - image_base, code)

            if candidate.mnemonic != "cmp" or candidate.size > 8 or not _is_memory(op0):
                continue

            if arch == "x64":
                valid_base = op0.base in ("rbp", "rsp")
                valid_value = (op1.kind == "imm" and op1.value == 1) or _is_register(op1)
            else:
                valid_base = op0.base == "ebp"
                valid_value = op1.kind == "imm" and op1.value == 1

            if valid_base and valid_value:
                return PatchMatch("SingleUser", candidate.ea - image_base, f"nop_{candidate.size}")

        break
    return None


def locate_def_policy(
    instructions: Sequence[Instruction], arch: str, image_base: int
) -> Optional[PatchMatch]:
    """Locate CDefPolicy::Query, including the 0x63c/0x638 register-pair form."""
    mov_base: Optional[str] = None
    mov_target: Optional[str] = None
    mov_base2: Optional[str] = None
    mov_target2: Optional[str] = None

    for index, insn in enumerate(instructions):
        op0 = insn.operand(0)
        op1 = insn.operand(1)

        if insn.mnemonic == "cmp":
            reg1: Optional[str] = None
            reg2: Optional[str] = None
            use_previous = False

            if arch == "x64" and _is_memory(op0, 0x63C) and _is_register(op1):
                reg1, reg2 = op1.reg, op0.base
            elif arch == "x64" and _is_register(op0) and _is_memory(op1, 0x63C):
                reg1, reg2 = op0.reg, op1.base
            elif arch == "x86" and _is_register(op0) and _is_memory(op1, 0x320):
                reg1, reg2 = op0.reg, op1.base
            elif (
                arch == "x64"
                and mov_base is not None
                and mov_base == mov_base2
                and _is_register(op0)
                and _is_register(op1)
                and {op0.reg, op1.reg} == {mov_target, mov_target2}
            ):
                reg1, reg2 = mov_target2, mov_base2
                use_previous = True

            if not reg1 or not reg2 or index + 1 >= len(instructions):
                continue

            next_mnemonic = instructions[index + 1].mnemonic
            suffix = ""
            if next_mnemonic == "jnz":
                use_previous = True
                suffix = "_jmp"
            elif next_mnemonic not in ("jz", "pop"):
                continue

            patch_insn = instructions[index - 1] if use_previous and index else insn
            return PatchMatch(
                "DefPolicy",
                patch_insn.ea - image_base,
                f"CDefPolicy_Query_{reg1}_{reg2}{suffix}",
            )

        if arch == "x64" and insn.mnemonic == "mov" and _is_register(op0):
            if _is_memory(op1, 0x63C):
                mov_base, mov_target = op1.base, op0.reg
            elif _is_memory(op1, 0x638):
                mov_base2, mov_target2 = op1.base, op0.reg

    return None


def locate_local_only(
    instructions: Sequence[Instruction],
    arch: str,
    image_base: int,
    license_check_target: int,
) -> Optional[PatchMatch]:
    """Locate LocalOnly and handle the distinct JS and JNS control-flow layouts."""
    by_ea: Dict[int, int] = {insn.ea: index for index, insn in enumerate(instructions)}

    for call_index, call in enumerate(instructions):
        if call.mnemonic != "call" or call.operand(0).target != license_check_target:
            continue

        index = call_index + 1
        while index < len(instructions) and instructions[index].mnemonic == "mov":
            index += 1
        if index >= len(instructions) or instructions[index].mnemonic != "test":
            continue

        index += 1
        if index >= len(instructions):
            continue
        branch = instructions[index]
        branch_target = branch.operand(0).target
        fallthrough = branch.ea + branch.size
        if branch_target is None or branch.mnemonic not in ("js", "jns"):
            continue

        if branch.mnemonic == "jns":
            expected_target = fallthrough
            cmp_index = by_ea.get(branch_target)
        else:
            expected_target = branch_target
            cmp_index = by_ea.get(fallthrough)
        if cmp_index is None or instructions[cmp_index].mnemonic != "cmp":
            continue

        jz_index = cmp_index + 1
        if jz_index >= len(instructions):
            continue
        jz = instructions[jz_index]
        if jz.mnemonic != "jz" or jz.operand(0).target != expected_target:
            continue

        code = "jmpshort" if jz.size == 2 else "nopjmp"
        return PatchMatch("LocalOnly", jz.ea - image_base, code)

    return None


def uses_win8_cp_policy(instructions: Iterable[Instruction], arch: str) -> bool:
    if arch != "x86":
        return False
    for insn in instructions:
        op0 = insn.operand(0)
        op1 = insn.operand(1)
        if (
            insn.mnemonic == "mov"
            and _is_register(op0)
            and _is_memory(op1)
            and op1.base == "ebp"
            and (op1.displacement or 0) > 0
        ):
            return True
        if insn.mnemonic == "test":
            break
    return False
