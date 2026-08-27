import unittest

from termsrv_patch_locator.core import (
    Instruction,
    Operand,
    locate_def_policy,
    locate_def_policy_arm64,
    locate_local_only,
    locate_local_only_arm64,
    locate_single_user,
    locate_single_user_arm64,
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


class Arm64Tests(unittest.TestCase):
    def test_single_user(self):
        instructions = [
            insn(0x900, 4, "bl", near(BASE + 0xA00)),
            insn(0x904, 4, "mov", reg("x1"), reg("x0")),
            insn(0x908, 4, "bl", near(BASE + 0xB00)),
        ]
        match = locate_single_user_arm64(
            instructions, BASE, {BASE + 0xA00}, {BASE + 0xB00}
        )
        self.assertEqual((match.offset, match.code), (0x908, "MovX0_1"))

    def test_single_user_26100_sequence(self):
        instructions = [
            insn(0x14B890, 4, "mov", reg("w19"), imm(0)),
            insn(0x14B894, 4, "mov", reg("w20"), imm(1)),
            insn(0x14B898, 4, "bl", near(BASE + 0x220000)),
            insn(0x14B89C, 4, "mov", reg("w8"), imm(0x11C)),
            insn(0x14B8BC, 4, "bl", near(BASE + 0x221000)),
            insn(0x14B8C0, 4, "mov", reg("w1"), imm(0x40)),
            insn(0x14B8C4, 4, "mov", reg("x2"), reg("x0")),
            insn(0x14B8C8, 4, "add", reg("x0"), reg("sp"), imm(0x48)),
            insn(0x14B8CC, 4, "bl", near(BASE + 0x222000)),
            insn(0x14B8D0, 4, "cbz", reg("w0"), near(BASE + 0x14BA34)),
        ]
        match = locate_single_user_arm64(
            instructions, BASE, {BASE + 0x220000}, {BASE + 0x222000}
        )
        self.assertEqual((match.offset, match.code), (0x14B8CC, "MovX0_1"))

    def test_def_policy_26100_sequence(self):
        instructions = [
            insn(0x872F8, 4, "ldr", reg("w4"), mem("x20", 0x644)),
            insn(0x87300, 4, "add", reg("x17"), reg("x20"), imm(0x638)),
            insn(0x87304, 4, "ldp", reg("w3"), reg("w2"), mem("x17", 0)),
            insn(0x87308, 4, "adrp", reg("x8"), imm(0x1B6000)),
            insn(0x8730C, 4, "add", reg("x1"), reg("x8"), imm(0xDA0)),
            insn(0x87310, 4, "mov", reg("w0"), imm(1)),
            insn(0x87314, 4, "mov", reg("w21"), imm(0)),
            insn(0x87318, 4, "bl", near(BASE + 0x8B4B8)),
            insn(0x8731C, 4, "ldr", reg("w8"), mem("x20", 0x644)),
            insn(0x87320, 4, "str", reg("w8"), mem("x22", 0)),
            insn(0x87324, 4, "add", reg("x17"), reg("x20"), imm(0x638)),
            insn(0x87328, 4, "ldp", reg("w3"), reg("w2"), mem("x17", 0)),
            insn(0x8732C, 4, "cmp", reg("w2"), reg("w3")),
            insn(0x87330, 4, "b.ne", near(BASE + 0x87348)),
        ]
        match = locate_def_policy_arm64(instructions, BASE)
        self.assertEqual(
            (match.offset, match.code), (0x87324, "CDefPolicy_Query_w3_x20_b")
        )

    def test_def_policy_26100_ida_missing_ldp_base(self):
        instructions = [
            insn(0x87324, 4, "add", reg("x17"), reg("x20"), imm(0x638)),
            insn(0x87328, 4, "ldp", reg("w3"), reg("w2"), Operand("mem")),
            insn(0x8732C, 4, "cmp", reg("w2"), reg("w3")),
            insn(0x87330, 4, "B.NE", near(BASE + 0x87348)),
        ]
        match = locate_def_policy_arm64(instructions, BASE)
        self.assertEqual(
            (match.offset, match.code), (0x87324, "CDefPolicy_Query_w3_x20_b")
        )

    def test_def_policy_w9_x8_example(self):
        instructions = [
            insn(0x877AC, 4, "add", reg("x17"), reg("x8"), imm(0x638)),
            insn(0x877B0, 4, "ldp", reg("w9"), reg("w8"), mem("x17", 0)),
            insn(0x877B4, 4, "cmp", reg("w8"), reg("w9")),
            insn(0x877B8, 4, "B.NE", near(BASE + 0x877D0)),
        ]
        match = locate_def_policy_arm64(instructions, BASE)
        self.assertEqual(
            (match.offset, match.code), (0x877AC, "CDefPolicy_Query_w9_x8_b")
        )

    def test_def_policy_ldr_layout(self):
        instructions = [
            insn(0xA00, 4, "ldr", reg("w9"), mem("x19", 0x638)),
            insn(0xA04, 4, "ldr", reg("w10"), mem("x19", 0x63C)),
            insn(0xA08, 4, "cmp", reg("w10"), reg("w9")),
            insn(0xA0C, 4, "b.ne", near(BASE + 0xA30)),
        ]
        match = locate_def_policy_arm64(instructions, BASE)
        self.assertEqual(
            (match.offset, match.code), (0xA00, "CDefPolicy_Query_w9_x19_b")
        )

    def test_def_policy_ldp_layout(self):
        instructions = [
            insn(0xB00, 4, "add", reg("x8"), reg("x20"), imm(0x638)),
            insn(0xB04, 4, "ldp", reg("w11"), reg("w12"), mem("x8", 0)),
            insn(0xB08, 4, "cmp", reg("w11"), reg("w12")),
            insn(0xB0C, 4, "b.eq", near(BASE + 0xB30)),
        ]
        match = locate_def_policy_arm64(instructions, BASE)
        self.assertEqual(
            (match.offset, match.code), (0xB00, "CDefPolicy_Query_w11_x20")
        )

    def test_local_only(self):
        target = BASE + 0xC40
        instructions = [
            insn(0xC00, 4, "bl", near(BASE + 0xD00)),
            insn(0xC04, 4, "mov", reg("w8"), reg("w0")),
            insn(0xC08, 4, "tbnz", reg("w8"), imm(31), near(target)),
            insn(0xC0C, 4, "ldr", reg("w9"), mem("x20", 0)),
            insn(0xC10, 4, "cbz", reg("w9"), near(target)),
        ]
        match = locate_local_only_arm64(
            instructions, BASE, {BASE + 0xD00}
        )
        self.assertEqual((match.offset, match.code), (0xC10, "B_48"))


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
