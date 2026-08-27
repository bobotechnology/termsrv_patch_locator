import unittest

from termsrv_patch_locator.output import (
    format_patch_block,
    format_slinit_hook,
    format_slinit_section,
    join_blocks,
)


class PatchOutputTests(unittest.TestCase):
    def test_version_patch_order_without_comments(self):
        blocks = join_blocks([
            format_patch_block("LocalOnly", "x64", [
                "LocalOnlyPatch.x64=1",
                "LocalOnlyOffset.x64=9B7E1",
                "LocalOnlyCode.x64=jmpshort",
            ]),
            format_patch_block("SingleUser", "x64", [
                "SingleUserPatch.x64=1",
                "SingleUserOffset.x64=123",
                "SingleUserCode.x64=nop_4",
            ]),
            format_patch_block("DefPolicy", "x64", [
                "DefPolicyPatch.x64=1",
                "DefPolicyOffset.x64=456",
                "DefPolicyCode.x64=CDefPolicy_Query_r9d_rdi_jmp",
            ]),
            format_slinit_hook("x64", 0x789),
        ])
        self.assertLess(blocks.index("LocalOnlyPatch.x64=1"), blocks.index("SingleUserPatch.x64=1"))
        self.assertLess(blocks.index("SingleUserPatch.x64=1"), blocks.index("DefPolicyPatch.x64=1"))
        self.assertLess(blocks.index("DefPolicyPatch.x64=1"), blocks.index("SLInitHook.x64=1"))
        self.assertNotIn("", blocks)
        self.assertFalse(any(line.startswith((";", "#")) for line in blocks))

    def test_slinit_order_alignment_and_no_comments(self):
        addresses = {
            "bInitialized": 0x10,
            "bServerSku": 0x20,
            "lMaxUserSessions": 0x30,
            "bAppServerAllowed": 0x40,
            "bRemoteConnAllowed": 0x50,
            "bMultimonAllowed": 0x60,
            "ulMaxDebugSessions": 0x70,
            "bFUSEnabled": 0x80,
        }
        lines = format_slinit_section("10.0.22621.608", "x64", addresses)
        self.assertEqual(lines[0], "[10.0.22621.608-SLInit]")
        keys = [line.split("=", 1)[0].rstrip() for line in lines if "=" in line]
        self.assertEqual(keys, [
            "bInitialized.x64",
            "bServerSku.x64",
            "lMaxUserSessions.x64",
            "bAppServerAllowed.x64",
            "bRemoteConnAllowed.x64",
            "bMultimonAllowed.x64",
            "ulMaxDebugSessions.x64",
            "bFUSEnabled.x64",
        ])
        equals_columns = {line.index("=") for line in lines if "=" in line}
        self.assertEqual(len(equals_columns), 1)
        self.assertFalse(any(line.startswith((";", "#")) for line in lines))

    def test_missing_patch_preserves_error(self):
        self.assertEqual(
            format_patch_block("LocalOnly", "x64", ["ERROR: LocalOnlyPatch pattern not found"]),
            ["ERROR: LocalOnlyPatch pattern not found"],
        )


if __name__ == "__main__":
    unittest.main()
