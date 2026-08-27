# -*- coding: utf-8 -*-
"""IDA plugin that locates termsrv.dll offsets used by RDP Wrapper."""

import ctypes
import datetime
import fnmatch
import os
import re
from ctypes import wintypes

import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_lines
import ida_nalt
import ida_ua
import idautils
import idc

from termsrv_patch_locator.core import (
    Instruction,
    Operand,
    PatchMatch,
    locate_def_policy,
    locate_def_policy_arm64,
    locate_local_only,
    locate_local_only_arm64,
    locate_single_user,
    locate_single_user_arm64,
    uses_win8_cp_policy,
)
from termsrv_patch_locator.output import (
    format_patch_block,
    format_slinit_hook,
    format_slinit_section,
    join_blocks,
)


PLUGIN_NAME = "Termsrv RDP Patch Locator"
DEBUG_MODE = False

INI_TEMPLATE = """[Main]
Updated=2021-06-23
LogFile=\\rdpwrap.txt
SLPolicyHookNT60=1
SLPolicyHookNT61=1

[PatchCodes]
nop=90
Zero=00
jmpshort=EB
nopjmp=90E9
CDefPolicy_Query_edx_ecx=BA000100008991200300005E90
CDefPolicy_Query_eax_rcx_jmp=B80001000089813806000090EB
CDefPolicy_Query_eax_esi=B80001000089862003000090
CDefPolicy_Query_eax_rdi=B80001000089873806000090
CDefPolicy_Query_eax_ecx=B80001000089812403000090
CDefPolicy_Query_eax_ecx_jmp=B800010000898120030000EB0E
CDefPolicy_Query_eax_rcx=B80001000089813806000090
CDefPolicy_Query_edi_rcx=BF0001000089B938060000909090
CDefPolicy_Query_eax_rdi_jmp=B80001000089873806000090EB
CDefPolicy_Query_r9d_rdi_jmp=C7873806000000010000EB
nop_3=909090
nop_4=90909090
nop_7=90909090909090
mov_eax_1_nop_0=B801000000
mov_eax_1_nop_1=B80100000090
mov_eax_1_nop_2=B8010000009090
pop_eax_add_esp_12_nop_1=5883C40C90
pop_eax_add_esp_12_nop_2=5883C40C9090
pop_eax_add_esp_12_nop_3=5883C40C909090

[SLInit]
bServerSku=1
bRemoteConnAllowed=1
bFUSEnabled=1
bAppServerAllowed=1
bMultimonAllowed=1
lMaxUserSessions=0
ulMaxDebugSessions=0
bInitialized=1

[SLPolicy]
TerminalServices-RemoteConnectionManager-AllowRemoteConnections=1
TerminalServices-RemoteConnectionManager-AllowMultipleSessions=1
TerminalServices-RemoteConnectionManager-AllowAppServerMode=1
TerminalServices-RemoteConnectionManager-AllowMultimon=1
TerminalServices-RemoteConnectionManager-MaxUserSessions=0
TerminalServices-RemoteConnectionManager-ce0ad219-4670-4988-98fb-89b14c2f072b-MaxSessions=0
TerminalServices-RemoteConnectionManager-45344fe7-00e6-4ac6-9f01-d01fd4ffadfb-MaxSessions=2
TerminalServices-RDP-7-Advanced-Compression-Allowed=1
TerminalServices-RemoteConnectionManager-45344fe7-00e6-4ac6-9f01-d01fd4ffadfb-LocalOnly=0
TerminalServices-RemoteConnectionManager-8dc86f1d-9969-4379-91c1-06fe1dc60575-MaxSessions=1000
TerminalServices-DeviceRedirection-Licenses-TSEasyPrintAllowed=1
TerminalServices-DeviceRedirection-Licenses-PnpRedirectionAllowed=1
TerminalServices-DeviceRedirection-Licenses-TSMFPluginAllowed=1
TerminalServices-RemoteConnectionManager-UiEffects-DWMRemotingAllowed=1
TerminalServices-RemoteApplications-ClientSku-RAILAllowed=1

"""

SLINIT_VARS = (
    "bInitialized",
    "bServerSku",
    "lMaxUserSessions",
    "bAppServerAllowed",
    "bRemoteConnAllowed",
    "bMultimonAllowed",
    "ulMaxDebugSessions",
    "bFUSEnabled",
)


def debug_log(message):
    if DEBUG_MODE:
        print("[DEBUG] " + message)


def get_imagebase():
    return ida_nalt.get_imagebase()


def get_arch():
    if hasattr(ida_ida, "inf_get_procname"):
        processor = ida_ida.inf_get_procname().lower()
    else:
        processor = ida_idaapi.get_inf_structure().procname.lower()
    if hasattr(ida_ida, "inf_get_app_bitness"):
        bitness = ida_ida.inf_get_app_bitness()
    else:
        info = ida_idaapi.get_inf_structure()
        bitness = 64 if info.is_64bit() else 32 if info.is_32bit() else 16
    if processor in ("arm", "armb"):
        return "arm64" if bitness == 64 else "arm"
    return "x64" if bitness == 64 else "x86"


def _short_demangle_mask():
    try:
        return idc.get_inf_attr(idc.INF_SHORT_DN)
    except (AttributeError, TypeError):
        return idc.INF_SHORT_DN


def _display_name(name):
    demangled = idc.demangle_name(name, _short_demangle_mask())
    return demangled or name


def find_func_eas(*patterns):
    lowered = tuple(pattern.lower() for pattern in patterns)
    matches = []
    seen = set()
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if not name:
            continue
        display = _display_name(name).lower()
        if (
            ea not in seen
            and any(fnmatch.fnmatch(display, "*" + pattern + "*") for pattern in lowered)
        ):
            debug_log("Function {} at 0x{:X}".format(_display_name(name), ea))
            matches.append(ea)
            seen.add(ea)
    return matches


def find_func_ea(*patterns):
    matches = find_func_eas(*patterns)
    return matches[0] if matches else None


def find_name_eas(*patterns):
    lowered = tuple(pattern.lower() for pattern in patterns)
    return {
        ea
        for ea, name in idautils.Names()
        if name and any(fnmatch.fnmatch(name.lower(), pattern) for pattern in lowered)
    }


def find_name_ea(*patterns):
    matches = find_name_eas(*patterns)
    return next(iter(matches), ida_idaapi.BADADDR)


def find_var_ea(name):
    needle = "cslquery::" + name.lower()
    for ea, symbol in idautils.Names():
        if symbol and needle in _display_name(symbol).lower():
            return ea
    return None


def _register_name(reg, dtype=None, address=False):
    if reg is None or reg < 0:
        return None
    if address:
        width = 8 if get_arch() in ("x64", "arm64") else 4
    else:
        width = ida_ua.get_dtype_size(dtype) if dtype is not None else 0
        if width <= 0:
            width = 8 if get_arch() in ("x64", "arm64") else 4
    return ida_idp.get_reg_name(reg, width)


def _operand(insn, op):
    if op.type == ida_ua.o_reg:
        return Operand("reg", reg=_register_name(op.reg, op.dtype))
    if op.type == ida_ua.o_imm:
        return Operand("imm", value=op.value)
    if op.type in (ida_ua.o_phrase, ida_ua.o_displ):
        return Operand(
            "mem",
            base=_register_name(op.phrase, address=True),
            displacement=op.addr,
            target=op.addr,
        )
    if op.type == ida_ua.o_mem:
        return Operand("mem", displacement=op.addr, target=op.addr)
    if op.type in (ida_ua.o_near, ida_ua.o_far):
        return Operand("near", target=op.addr)
    return Operand("void")


def decode_instruction(ea):
    insn = idautils.DecodeInstruction(ea)
    if not insn:
        return None
    operands = tuple(_operand(insn, op) for op in insn.ops if op.type != ida_ua.o_void)
    mnemonic = idc.print_insn_mnem(ea).lower()
    if get_arch() == "arm64" and mnemonic == "b":
        line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "")
        displayed = line.strip().split(None, 1)
        if displayed and displayed[0].lower().startswith("b."):
            mnemonic = displayed[0].lower()
    return Instruction(ea, insn.size, mnemonic, operands)


def collect_function(ea, max_bytes=None):
    function = ida_funcs.get_func(ea)
    if not function:
        return []
    end = function.end_ea
    if max_bytes is not None:
        end = min(end, ea + max_bytes)
    result = []
    cursor = ea
    while cursor < end:
        insn = decode_instruction(cursor)
        if not insn:
            cursor = idc.next_head(cursor, end)
            if cursor == ida_idaapi.BADADDR:
                break
            continue
        result.append(insn)
        cursor += insn.size
    return result


def _call_target_candidates(ea):
    if ea in (None, ida_idaapi.BADADDR):
        return set()
    candidates = {ea}
    for xref in idautils.XrefsTo(ea):
        source = decode_instruction(xref.frm)
        if source and source.mnemonic == "jmp":
            candidates.add(xref.frm)
            continue
        if get_arch() == "arm64":
            function = ida_funcs.get_func(xref.frm)
            if function and function.end_ea - function.start_ea <= 16:
                candidates.add(function.start_ea)
    return candidates


def _first_match(matcher, instruction_sets, *args):
    for instructions in instruction_sets:
        result = matcher(instructions, *args)
        if result:
            return result.ini_lines(get_arch())
    return None


def patch_single_user():
    arch = get_arch()
    if arch == "arm":
        return ["ERROR: SingleUserPatch ARM32 is not supported"]
    memset_symbols = set(find_func_eas("memset"))
    memset_symbols.update(find_name_eas(
        "memset", "memset_0", "_memset", "__imp_memset", "__imp__memset@*"
    ))
    if not memset_symbols:
        return ["ERROR: memset not found"]

    verify_symbols = find_name_eas(
        "verifyversioninfow",
        "_verifyversioninfow",
        "verifyversioninfow_0",
        "_verifyversioninfow_0",
        "__imp_verifyversioninfow",
        "__imp__verifyversioninfow@*",
    )
    verify_targets = set()
    for ea in verify_symbols:
        verify_targets.update(_call_target_candidates(ea))
    memset_targets = set()
    for ea in memset_symbols:
        memset_targets.update(_call_target_candidates(ea))

    functions = []
    seen_functions = set()
    for pattern in (
        "csessionarbitrationhelper::issinglesessionperuserenabled",
        "cutils::issinglesessionperuser",
    ):
        for ea in find_func_eas(pattern):
            if ea not in seen_functions:
                functions.append(collect_function(ea, 256))
                seen_functions.add(ea)

    for instructions in functions:
        if arch == "arm64":
            match = locate_single_user_arm64(
                instructions, get_imagebase(), memset_targets, verify_targets - {None}
            )
            if match:
                return match.ini_lines(arch)
            continue
        for memset_target in memset_targets:
            for verify_target in verify_targets:
                match = locate_single_user(
                    instructions, arch, get_imagebase(), memset_target, verify_target
                )
                if match:
                    return match.ini_lines(arch)
    return ["ERROR: SingleUserPatch pattern not found"]


def _normalize_arm_operand(ea, index):
    return re.sub(r"\s+", "", idc.print_operand(ea, index).lower())


def locate_def_policy_arm64_ida(ea, max_bytes=128):
    """Fallback for IDA ARM64 operand encodings that do not map cleanly to op_t."""
    function = ida_funcs.get_func(ea)
    if not function:
        return None
    end = min(function.end_ea, ea + max_bytes)
    cursor = ea
    while cursor + 12 < end:
        if idc.print_insn_mnem(cursor).lower() != "add":
            cursor += 4
            continue

        add_dst = _normalize_arm_operand(cursor, 0)
        add_base = _normalize_arm_operand(cursor, 1)
        add_imm = _normalize_arm_operand(cursor, 2)
        debug_log(
            "[DefPolicy ARM64 text] 0x{:X}: add {}, {}, {}".format(
                cursor, add_dst, add_base, add_imm
            )
        )
        if not re.fullmatch(r"x(?:[12]?\d|30)", add_dst):
            cursor += 4
            continue
        if not re.fullmatch(r"x(?:[12]?\d|30)", add_base):
            cursor += 4
            continue
        try:
            immediate_text = add_imm.lstrip("#")
            immediate = (
                int(immediate_text[:-1], 16)
                if immediate_text.endswith("h")
                else int(immediate_text, 0)
            )
        except ValueError:
            cursor += 4
            continue
        if immediate != 0x638:
            cursor += 4
            continue

        load_ea, compare_ea, branch_ea = cursor + 4, cursor + 8, cursor + 12
        if idc.print_insn_mnem(load_ea).lower() != "ldp":
            cursor += 4
            continue
        reg1 = _normalize_arm_operand(load_ea, 0)
        reg_other = _normalize_arm_operand(load_ea, 1)
        load_mem = _normalize_arm_operand(load_ea, 2)
        if not re.fullmatch(r"w(?:[12]?\d|30)", reg1):
            cursor += 4
            continue
        if not re.fullmatch(r"w(?:[12]?\d|30)", reg_other):
            cursor += 4
            continue
        if load_mem and add_dst not in load_mem:
            cursor += 4
            continue

        if idc.print_insn_mnem(compare_ea).lower() != "cmp":
            cursor += 4
            continue
        compared = {
            _normalize_arm_operand(compare_ea, 0),
            _normalize_arm_operand(compare_ea, 1),
        }
        if compared != {reg1, reg_other}:
            cursor += 4
            continue

        branch_line = ida_lines.tag_remove(idc.generate_disasm_line(branch_ea, 0) or "")
        branch_token = branch_line.strip().split(None, 1)[0].lower().replace(".", "") if branch_line.strip() else ""
        if branch_token not in ("beq", "bne"):
            cursor += 4
            continue
        suffix = "_b" if branch_token == "bne" else ""
        debug_log(
            "[DefPolicy ARM64 text] matched 0x{:X}: {}, {}, {}, {}".format(
                cursor, reg1, reg_other, add_base, branch_token
            )
        )
        return PatchMatch(
            "DefPolicy",
            cursor - get_imagebase(),
            "CDefPolicy_Query_{}_{}{}".format(reg1, add_base, suffix),
        )
    return None


def patch_def_policy():
    arch = get_arch()
    if arch == "arm":
        return ["ERROR: DefPolicyPatch ARM32 is not supported"]
    candidates = find_func_eas("cdefpolicy::query")
    if not candidates:
        return ["ERROR: CDefPolicy::Query not found"]
    for ea in candidates:
        instructions = collect_function(ea, 128)
        match = (
            locate_def_policy_arm64(instructions, get_imagebase())
            if arch == "arm64"
            else locate_def_policy(instructions, arch, get_imagebase())
        )
        if arch == "arm64" and not match:
            match = locate_def_policy_arm64_ida(ea, 128)
        if match:
            return match.ini_lines(arch)
    return ["ERROR: DefPolicyPatch pattern not found"]


def patch_local_only():
    arch = get_arch()
    if arch == "arm":
        return ["ERROR: LocalOnlyPatch ARM32 is not supported"]
    callers = find_func_eas("cenforcementcore::getinstanceoftslicense")
    targets = find_func_eas(
        "cslquery::islicensetypelocalonly", "cslquery::isterminaltypelocalonly"
    )
    if not callers or not targets:
        return ["ERROR: LocalOnly functions not found"]

    target_candidates = set()
    for target in targets:
        target_candidates.update(_call_target_candidates(target))

    for caller in callers:
        instructions = collect_function(caller)
        match = (
            locate_local_only_arm64(instructions, get_imagebase(), target_candidates)
            if arch == "arm64"
            else locate_local_only(instructions, arch, get_imagebase(), target_candidates)
        )
        if match:
            return match.ini_lines(arch)
    return ["ERROR: LocalOnlyPatch pattern not found"]


def get_file_version(file_path=None):
    file_path = file_path or idc.get_input_file_path()
    try:
        version = ctypes.WinDLL("version")

        class VS_FIXEDFILEINFO(ctypes.Structure):
            _fields_ = [(name, wintypes.DWORD) for name in (
                "dwSignature", "dwStrucVersion", "dwFileVersionMS", "dwFileVersionLS",
                "dwProductVersionMS", "dwProductVersionLS", "dwFileFlagsMask",
                "dwFileFlags", "dwFileOS", "dwFileType", "dwFileSubtype",
                "dwFileDateMS", "dwFileDateLS",
            )]

        size = version.GetFileVersionInfoSizeW(file_path, None)
        if not size:
            return None
        data = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(file_path, 0, size, data):
            return None
        buffer = ctypes.c_void_p()
        length = wintypes.UINT()
        if not version.VerQueryValueW(data, "\\", ctypes.byref(buffer), ctypes.byref(length)):
            return None
        info = ctypes.cast(buffer, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
        return (
            info.dwFileVersionMS >> 16,
            info.dwFileVersionMS & 0xFFFF,
            info.dwFileVersionLS >> 16,
            info.dwFileVersionLS & 0xFFFF,
        )
    except Exception as error:
        debug_log("Version read failed: {}".format(error))
        return None


def _append_and_print(lines, output):
    output.extend(lines)
    for line in lines:
        print(line)


def analyze_termsrv():
    version = get_file_version()
    if version is None:
        print("ERROR: Unable to read termsrv.dll file version")
        return

    arch = get_arch()
    version_text = ".".join(str(part) for part in version)
    raw_single_user = patch_single_user()
    raw_def_policy = patch_def_policy()

    if version[:2] <= (6, 1):
        results = ["[{}]".format(version_text)]
        results.extend(join_blocks([
            format_patch_block("SingleUser", arch, raw_single_user),
            format_patch_block("DefPolicy", arch, raw_def_policy),
        ]))
        _append_and_print(results, [])
        save_results_to_ini(version_text, results)
        return

    if version[:2] == (6, 2):
        blocks = [
            format_patch_block("SingleUser", arch, raw_single_user),
            format_patch_block("DefPolicy", arch, raw_def_policy),
        ]
        ea = find_func_ea("slgetwindowsinformationdwordwrapper")
        if ea is None:
            blocks.append(["ERROR: SLGetWindowsInformationDWORDWrapper not found"])
        else:
            function_name = "New_Win8SL_CP" if uses_win8_cp_policy(
                collect_function(ea, 128), arch
            ) else "New_Win8SL"
            blocks.append([
                "SLPolicyInternal.{}=1".format(arch),
                "SLPolicyOffset.{}={:X}".format(arch, ea - get_imagebase()),
                "SLPolicyFunc.{}={}".format(arch, function_name),
            ])
        results = ["[{}]".format(version_text)] + join_blocks(blocks)
        _append_and_print(results, [])
        save_results_to_ini(version_text, results)
        return

    raw_local_only = patch_local_only()
    init_ea = find_func_ea("cslquery::initialize")
    version_blocks = [
        format_patch_block("LocalOnly", arch, raw_local_only),
        format_patch_block("SingleUser", arch, raw_single_user),
        format_patch_block("DefPolicy", arch, raw_def_policy),
    ]

    if init_ea is None:
        version_blocks.append(["ERROR: CSLQuery::Initialize not found"])
        results = ["[{}]".format(version_text)] + join_blocks(version_blocks)
        _append_and_print(results, [])
        save_results_to_ini(version_text, results)
        return

    version_blocks.append(format_slinit_hook(arch, init_ea - get_imagebase()))
    addresses = {}
    for name in SLINIT_VARS:
        ea = find_var_ea(name)
        addresses[name] = ea - get_imagebase() if ea is not None else None

    results = ["[{}]".format(version_text)] + join_blocks(version_blocks)
    results.extend([""] + format_slinit_section(version_text, arch, addresses))
    _append_and_print(results, [])
    save_results_to_ini(version_text, results)


def save_results_to_ini(version_text, lines):
    try:
        folder = None
        try:
            import tkinter as tk
            from tkinter import filedialog

            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            folder = filedialog.askdirectory(title="Select folder to save .ini file", initialdir=os.getcwd())
            root.destroy()
        except ImportError:
            folder = os.path.join(os.getcwd(), "autogenerated")

        if not folder:
            print("Save cancelled by user.")
            return
        os.makedirs(folder, exist_ok=True)
        filename = "{}-autogenerated_{}.ini".format(version_text, get_arch())
        path = os.path.join(folder, filename)
        template = INI_TEMPLATE.replace(
            "Updated=2021-06-23", "Updated=" + datetime.datetime.now().strftime("%Y-%m-%d")
        )
        with open(path, "w", encoding="utf-8") as output:
            output.write(template)
            output.write("\n".join(lines))
            output.write("\n")
        print("Results saved to: " + path)
    except Exception as error:
        print("ERROR: Failed to save results to file: {}".format(error))


class TermsrvPatchPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC
    comment = "Locate patch points in termsrv.dll for RDP multi-session"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl+Alt+R"

    def init(self):
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        analyze_termsrv()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return TermsrvPatchPlugin()
