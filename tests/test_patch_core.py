import unittest

from termsrv_patch_core import (
    Instruction,
    Operand,
    locate_def_policy,
    locate_local_only,
    locate_single_user,
    uses_win8_cp_policy,
)


BASE = 0x180000000


def reg(name):
    return Operand("reg", reg=name)


def mem(base, displacement=0, target=None):
    return Operand("mem", base=base, displacement=displacement, target=target)


def imm(value):
    return Operand("imm", value=value)


def near(target):
    return Operand("near", target=target)


def insn(offset, size, mnemonic, *operands):
    return Instruction(BASE + offset, size, mnemonic, operands)


class SingleUserTests(unittest.TestCase):
    def test_x64_verify_version_call(self):
        instructions = [
            insn(0x100, 5, "call", near(BASE + 0x900)),
            insn(0x105, 3, "mov", reg("rcx"), reg("rax")),
            insn(0x108, 6, "call", mem("rip", target=BASE + 0xA00)),
        ]
        match = locate_single_user(
            instructions, "x64", BASE, BASE + 0x900, BASE + 0xA00
        )
        self.assertEqual((match.offset, match.code), (0x108, "mov_eax_1_nop_1"))

    def test_x86_cmp_fallback(self):
        instructions = [
            insn(0x200, 5, "call", near(BASE + 0x900)),
            insn(0x205, 4, "cmp", mem("ebp", 0x10), imm(1)),
        ]
        match = locate_single_user(instructions, "x86", BASE, BASE + 0x900, None)
        self.assertEqual((match.offset, match.code), (0x205, "nop_4"))


class DefPolicyTests(unittest.TestCase):
    def test_direct_x64_cmp(self):
        instructions = [
            insn(0x300, 7, "cmp", mem("rdi", 0x63C), reg("eax")),
            insn(0x307, 2, "jz", near(BASE + 0x320)),
        ]
        match = locate_def_policy(instructions, "x64", BASE)
        self.assertEqual((match.offset, match.code), (0x300, "CDefPolicy_Query_eax_rdi"))

    def test_register_pair_jnz_uses_previous_instruction(self):
        instructions = [
            insn(0x400, 7, "mov", reg("eax"), mem("rdi", 0x63C)),
            insn(0x407, 7, "mov", reg("r9d"), mem("rdi", 0x638)),
            insn(0x40E, 3, "cmp", reg("eax"), reg("r9d")),
            insn(0x411, 2, "jnz", near(BASE + 0x430)),
        ]
        match = locate_def_policy(instructions, "x64", BASE)
        self.assertEqual((match.offset, match.code), (0x407, "CDefPolicy_Query_r9d_rdi_jmp"))


class LocalOnlyTests(unittest.TestCase):
    def test_js_layout(self):
        instructions = [
            insn(0x500, 5, "call", near(BASE + 0x900)),
            insn(0x505, 3, "mov", reg("eax"), reg("ecx")),
            insn(0x508, 2, "test", reg("eax"), reg("eax")),
            insn(0x50A, 2, "js", near(BASE + 0x530)),
            insn(0x50C, 3, "cmp", reg("eax"), imm(1)),
            insn(0x50F, 2, "jz", near(BASE + 0x530)),
            insn(0x530, 1, "ret"),
        ]
        match = locate_local_only(instructions, "x64", BASE, BASE + 0x900)
        self.assertEqual((match.offset, match.code), (0x50F, "jmpshort"))

    def test_call_thunk_target_is_accepted(self):
        instructions = [
            insn(0x580, 5, "call", near(BASE + 0x980)),
            insn(0x585, 2, "test", reg("eax"), reg("eax")),
            insn(0x587, 2, "js", near(BASE + 0x5A0)),
            insn(0x589, 3, "cmp", reg("eax"), imm(1)),
            insn(0x58C, 2, "jz", near(BASE + 0x5A0)),
            insn(0x5A0, 1, "ret"),
        ]
        match = locate_local_only(
            instructions, "x64", BASE, {BASE + 0x900, BASE + 0x980}
        )
        self.assertEqual((match.offset, match.code), (0x58C, "jmpshort"))

    def test_pattern_after_first_256_bytes(self):
        instructions = [insn(offset, 1, "nop") for offset in range(0x700, 0x810)]
        instructions.extend([
            insn(0x810, 5, "call", near(BASE + 0x900)),
            insn(0x815, 2, "test", reg("eax"), reg("eax")),
            insn(0x817, 2, "js", near(BASE + 0x830)),
            insn(0x819, 3, "cmp", reg("eax"), imm(0)),
            insn(0x81C, 2, "jz", near(BASE + 0x830)),
            insn(0x830, 1, "ret"),
        ])
        match = locate_local_only(instructions, "x64", BASE, BASE + 0x900)
        self.assertEqual((match.offset, match.code), (0x81C, "jmpshort"))

    def test_jns_layout(self):
        instructions = [
            insn(0x600, 5, "call", near(BASE + 0x900)),
            insn(0x605, 2, "test", reg("eax"), reg("eax")),
            insn(0x607, 2, "jns", near(BASE + 0x620)),
            insn(0x609, 1, "ret"),
            insn(0x620, 3, "cmp", reg("eax"), imm(1)),
            insn(0x623, 6, "jz", near(BASE + 0x609)),
        ]
        match = locate_local_only(instructions, "x64", BASE, BASE + 0x900)
        self.assertEqual((match.offset, match.code), (0x623, "nopjmp"))


class SLPolicyTests(unittest.TestCase):
    def test_win8_cp_pattern(self):
        instructions = [
            insn(0x700, 3, "mov", reg("eax"), mem("ebp", 0x20)),
            insn(0x703, 2, "test", reg("eax"), reg("eax")),
        ]
        self.assertTrue(uses_win8_cp_policy(instructions, "x86"))
        self.assertFalse(uses_win8_cp_policy(instructions, "x64"))


if __name__ == "__main__":
    unittest.main()
