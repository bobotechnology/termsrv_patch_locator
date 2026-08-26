# -*- coding: utf-8 -*-
"""IDA plugin that locates termsrv.dll offsets used by RDP Wrapper."""

import ctypes
import datetime
import fnmatch
import os
from ctypes import wintypes

import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_nalt
import ida_ua
import idautils
import idc

from termsrv_patch_core import (
    Instruction,
    Operand,
    locate_def_policy,
    locate_local_only,
    locate_single_user,
    uses_win8_cp_policy,
)


PLUGIN_NAME = "Termsrv RDP Patch Locator"
DEBUG_MODE = False

INI_TEMPLATE = """[Main]
Updated=2021-06-23
LogFile=\\rdpwrap.txt
SLPolicyHookNT60=1
SLPolicyHookNT61=1

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

"""

SLINIT_VARS = (
    "bServerSku",
    "bRemoteConnAllowed",
    "bFUSEnabled",
    "bAppServerAllowed",
    "bMultimonAllowed",
    "lMaxUserSessions",
    "ulMaxDebugSessions",
    "bInitialized",
)


def debug_log(message):
    if DEBUG_MODE:
        print("[DEBUG] " + message)


def get_imagebase():
    return ida_nalt.get_imagebase()


def get_arch():
    if hasattr(ida_ida, "inf_is_32bit_exactly"):
        return "x86" if ida_ida.inf_is_32bit_exactly() else "x64"
    return "x86" if ida_idaapi.get_inf_structure().is_32bit() else "x64"


def _short_demangle_mask():
    try:
        return idc.get_inf_attr(idc.INF_SHORT_DN)
    except (AttributeError, TypeError):
        return idc.INF_SHORT_DN


def _display_name(name):
    demangled = idc.demangle_name(name, _short_demangle_mask())
    return demangled or name


def find_func_ea(*patterns):
    lowered = tuple(pattern.lower() for pattern in patterns)
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if not name:
            continue
        display = _display_name(name).lower()
        if any(fnmatch.fnmatch(display, "*" + pattern + "*") for pattern in lowered):
            debug_log("Function {} at 0x{:X}".format(_display_name(name), ea))
            return ea
    return None


def find_name_ea(*patterns):
    lowered = tuple(pattern.lower() for pattern in patterns)
    for ea, name in idautils.Names():
        if name and any(fnmatch.fnmatch(name.lower(), pattern) for pattern in lowered):
            return ea
    return ida_idaapi.BADADDR


def find_var_ea(name):
    needle = "cslquery::" + name.lower()
    for ea, symbol in idautils.Names():
        if symbol and needle in _display_name(symbol).lower():
            return ea
    return None


def _register_name(reg, dtype):
    if reg is None or reg < 0:
        return None
    width = ida_ua.get_dtype_size(dtype)
    if width <= 0:
        width = 8 if get_arch() == "x64" else 4
    return ida_idp.get_reg_name(reg, width)


def _operand(insn, op):
    if op.type == ida_ua.o_reg:
        return Operand("reg", reg=_register_name(op.reg, op.dtype))
    if op.type == ida_ua.o_imm:
        return Operand("imm", value=op.value)
    if op.type in (ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ):
        base = _register_name(op.reg, op.dtype) if op.type != ida_ua.o_mem else None
        return Operand("mem", base=base, displacement=op.addr, target=op.addr)
    if op.type in (ida_ua.o_near, ida_ua.o_far):
        return Operand("near", target=op.addr)
    return Operand("void")


def decode_instruction(ea):
    insn = idautils.DecodeInstruction(ea)
    if not insn:
        return None
    operands = tuple(_operand(insn, op) for op in insn.ops if op.type != ida_ua.o_void)
    return Instruction(ea, insn.size, idc.print_insn_mnem(ea).lower(), operands)


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
    return candidates


def _first_match(matcher, instruction_sets, *args):
    for instructions in instruction_sets:
        result = matcher(instructions, *args)
        if result:
            return result.ini_lines(get_arch())
    return None


def patch_single_user():
    memset_ea = find_func_ea("memset")
    if memset_ea is None:
        memset_ea = find_name_ea("memset", "_memset", "__imp_memset", "__imp__memset@*")
    if memset_ea in (None, ida_idaapi.BADADDR):
        return ["ERROR: memset not found"]

    verify_ea = find_name_ea("__imp_verifyversioninfow", "__imp__verifyversioninfow@*")
    verify_targets = _call_target_candidates(verify_ea) if verify_ea != ida_idaapi.BADADDR else {None}
    memset_targets = _call_target_candidates(memset_ea)

    functions = []
    for pattern in (
        "csessionarbitrationhelper::issinglesessionperuserenabled",
        "cutils::issinglesessionperuser",
    ):
        ea = find_func_ea(pattern)
        if ea is not None:
            functions.append(collect_function(ea, 256))

    for instructions in functions:
        for memset_target in memset_targets:
            for verify_target in verify_targets:
                match = locate_single_user(
                    instructions, get_arch(), get_imagebase(), memset_target, verify_target
                )
                if match:
                    return match.ini_lines(get_arch())
    return ["ERROR: SingleUserPatch pattern not found"]


def patch_def_policy():
    ea = find_func_ea("cdefpolicy::query")
    if ea is None:
        return ["ERROR: CDefPolicy::Query not found"]
    match = locate_def_policy(collect_function(ea, 128), get_arch(), get_imagebase())
    return match.ini_lines(get_arch()) if match else ["ERROR: DefPolicyPatch pattern not found"]


def patch_local_only():
    caller = find_func_ea("cenforcementcore::getinstanceoftslicense")
    target = find_func_ea(
        "cslquery::islicensetypelocalonly", "cslquery::isterminaltypelocalonly"
    )
    if caller is None or target is None:
        return ["ERROR: LocalOnly functions not found"]
    match = locate_local_only(
        collect_function(caller, 256), get_arch(), get_imagebase(), target
    )
    return match.ini_lines(get_arch()) if match else ["ERROR: LocalOnlyPatch pattern not found"]


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
    results = ["[{}]".format(version_text)]
    print(results[0])

    _append_and_print(patch_single_user(), results)
    _append_and_print(patch_def_policy(), results)

    if version[:2] <= (6, 1):
        save_results_to_ini(version_text, results)
        return

    if version[:2] == (6, 2):
        ea = find_func_ea("slgetwindowsinformationdwordwrapper")
        if ea is None:
            _append_and_print(["ERROR: SLGetWindowsInformationDWORDWrapper not found"], results)
        else:
            function_name = "New_Win8SL_CP" if uses_win8_cp_policy(
                collect_function(ea, 128), arch
            ) else "New_Win8SL"
            _append_and_print([
                "SLPolicyInternal.{}=1".format(arch),
                "SLPolicyOffset.{}={:X}".format(arch, ea - get_imagebase()),
                "SLPolicyFunc.{}={}".format(arch, function_name),
            ], results)
        save_results_to_ini(version_text, results)
        return

    _append_and_print(patch_local_only(), results)
    init_ea = find_func_ea("cslquery::initialize")
    if init_ea is None:
        _append_and_print(["ERROR: CSLQuery::Initialize not found"], results)
        save_results_to_ini(version_text, results)
        return

    _append_and_print([
        "SLInitHook.{}=1".format(arch),
        "SLInitOffset.{}={:X}".format(arch, init_ea - get_imagebase()),
        "SLInitFunc.{}=New_CSLQuery_Initialize".format(arch),
        "",
        "[SLInit]",
        "bServerSku=1",
        "bRemoteConnAllowed=1",
        "bFUSEnabled=1",
        "bAppServerAllowed=1",
        "bMultimonAllowed=1",
        "lMaxUserSessions=0",
        "ulMaxDebugSessions=0",
        "bInitialized=1",
        "",
        "[{}-SLInit]".format(version_text),
    ], results)

    for name in SLINIT_VARS:
        ea = find_var_ea(name)
        line = "{}.{}={:X}".format(name, arch, ea - get_imagebase()) if ea is not None else "ERROR: {} not found".format(name)
        _append_and_print([line], results)

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
