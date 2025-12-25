# -*- coding: utf-8 -*-
#
# Termsrv.dll RDP Multi-session Patch Locator
# Accurately ported from original C++ logic
# Fully compatible with IDA 7.0 ~ 9.0+
#
# Author: 星野凛 (Luna)
# Note: Requires PDB symbols loaded in IDA!
#       Add save to ini file feature

import idaapi
import ida_idaapi
import idautils
import idc
import ida_ua
import ctypes
from ctypes import wintypes
import fnmatch
import datetime
import os
import ida_ida

PLUGIN_NAME = "Termsrv RDP Patch Locator"
DEBUG_MODE = False

# 内置的模板内容
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
nop_3=909090
nop_7=90909090909090
mov_eax_1_nop_1=B80100000090
mov_eax_1_nop_2=B8010000009090
nop_4=90909090
pop_eax_add_esp_12_nop_2=5883C40C9090
CDefPolicy_Query_eax_rdi_jmp=B80001000089873806000090EB

"""

def debug_log(msg: str):
    if DEBUG_MODE:
        print(f"[DEBUG] {msg}")

def get_imagebase():
    return idaapi.get_imagebase()

def get_arch():
    try:
        return "x86" if (ida_idaapi.get_inf_structure().is_32bit()) else "x64"
    except AttributeError:
        return "x86" if ida_ida.inf_is_32bit_exactly() else "x64"


def find_func_ea(pattern: str):
    debug_log(f"Search function: {pattern}")
    for func_ea in idautils.Functions():
        current_func_name = idc.get_func_name(func_ea)
        if not current_func_name:
            continue
        demangled_name = idc.demangle_name(current_func_name, idc.INF_SHORT_DN)
        display_name = demangled_name if demangled_name else current_func_name
        if fnmatch.fnmatch(display_name.lower(), f"*{pattern.lower()}*"):
            debug_log(f"  -> Match: {current_func_name} @ 0x{func_ea:X}")
            return func_ea
    debug_log(f"  -> Not found")
    return None

def find_name_ea(pattern: str) -> int:
    """Find EA by name with wildcard support (e.g., '__imp__memset@*')."""
    debug_log(f"[find_name_ea] Pattern: {pattern}")
    for addr, name in idautils.Names():
        if name and fnmatch.fnmatch(name.lower(), pattern.lower()):
            debug_log(f"    -> Matched: {name} @ 0x{addr:X}")
            return addr
    debug_log(f"    -> No match for: {pattern}")
    return idaapi.BADADDR

def get_import_stub_ea(func_name: str) -> int:
    """Get '__imp_*' stub EA for given function."""
    patterns = [
        f"__imp_{func_name}",
        f"__imp__{func_name}@*",
    ]
    for pattern in patterns:
        ea = find_name_ea(pattern)
        if ea != idaapi.BADADDR:
            return ea
    return idaapi.BADADDR

def decode_inst(ea):
    return idautils.DecodeInstruction(ea)

def get_insn_mnemonic(insn):
    try:
        return idaapi.print_insn_mnem(insn.ea)
    except Exception:
        return ""

def get_reg_id(name):
    return idautils.str2reg(name)

def get_file_version_windows_api(file_path=None):
    if file_path is None:
        file_path = idc.get_input_file_path()

    try:
        version = ctypes.WinDLL('version')
        
        class VS_FIXEDFILEINFO(ctypes.Structure):
            _fields_ = [
                ('dwSignature', wintypes.DWORD),
                ('dwStrucVersion', wintypes.DWORD),
                ('dwFileVersionMS', wintypes.DWORD),
                ('dwFileVersionLS', wintypes.DWORD),
                ('dwProductVersionMS', wintypes.DWORD),
                ('dwProductVersionLS', wintypes.DWORD),
                ('dwFileFlagsMask', wintypes.DWORD),
                ('dwFileFlags', wintypes.DWORD),
                ('dwFileOS', wintypes.DWORD),
                ('dwFileType', wintypes.DWORD),
                ('dwFileSubtype', wintypes.DWORD),
                ('dwFileDateMS', wintypes.DWORD),
                ('dwFileDateLS', wintypes.DWORD),
            ]
        
        GetFileVersionInfoSizeW = version.GetFileVersionInfoSizeW
        GetFileVersionInfoW = version.GetFileVersionInfoW
        VerQueryValueW = version.VerQueryValueW

        dwHandle = wintypes.DWORD()
        dwSize = GetFileVersionInfoSizeW(file_path, ctypes.byref(dwHandle))
        if dwSize == 0:
            return None

        lpData = ctypes.create_string_buffer(dwSize)
        if not GetFileVersionInfoW(file_path, 0, dwSize, lpData):
            return None

        lpBuffer = ctypes.c_void_p()
        puLen = wintypes.UINT()
        if VerQueryValueW(lpData, '\\', ctypes.byref(lpBuffer), ctypes.byref(puLen)):
            pFixedFileInfo = ctypes.cast(lpBuffer, ctypes.POINTER(VS_FIXEDFILEINFO))
            ms = pFixedFileInfo.contents.dwFileVersionMS
            ls = pFixedFileInfo.contents.dwFileVersionLS
            return (
                (ms >> 16) & 0xFFFF,
                ms & 0xFFFF,
                (ls >> 16) & 0xFFFF,
                ls & 0xFFFF
            )
    except Exception:
        pass
    return None

def get_file_version():
    try:
        ver = get_file_version_windows_api()
        if ver:
            return ver
    except Exception:
        pass
    return (6, 3, 0, 0)

def check_SLPolicyCP(func_ea):
    if get_arch() != "x86":
        return False

    for ea in idautils.FuncItems(func_ea):
        insn = decode_inst(ea)
        if not insn:
            continue
        if get_insn_mnemonic(insn) == "mov":
            op0, op1 = insn.ops[0], insn.ops[1]
            if op0.type == ida_ua.o_reg and op0.reg == get_reg_id("ebp") and \
               op1.type == ida_ua.o_mem and op1.specval == get_reg_id("ebp") and op1.addr > 0:
                next_insn = decode_inst(ea + insn.size)
                if next_insn and get_insn_mnemonic(next_insn) == "test":
                    return True
        if get_insn_mnemonic(insn) == "test":
            break
    return False

def patch_SingleUser():
    """Modified to return results instead of printing directly"""
    arch = get_arch()
    is_64 = (arch == "x64")
    debug_log(f"[SingleUserPatch] Start ({arch})")
    results = []

    memset_ea = find_func_ea("*memset*")
    if memset_ea is None:
        results.append("ERROR: memset not found")
        return results

    verify_imp_ea = get_import_stub_ea("VerifyVersionInfoW")
    if verify_imp_ea == idaapi.BADADDR:
        debug_log("[SingleUserPatch] WARNING: __imp_VerifyVersionInfoW not found")

    def try_scan_in_function(func_ea, func_name):
        debug_log(f"[SingleUserPatch] Trying: {func_name} @ 0x{func_ea:X}")
        for inst_addr in idautils.FuncItems(func_ea):
            insn = decode_inst(inst_addr)
            if not insn or get_insn_mnemonic(insn) != "call":
                continue

            called_addr = idaapi.BADADDR
            op = insn.ops[0]
            if op.type == ida_ua.o_near:
                called_addr = op.addr
            if called_addr != memset_ea:
                continue

            scan_cursor = inst_addr + insn.size
            for _ in range(30):
                next_insn = decode_inst(scan_cursor)
                if not next_insn:
                    break

                if is_64:
                    if (get_insn_mnemonic(next_insn) == "call"
                        and 5 <= next_insn.size <= 7
                        and next_insn.ops[0].type == ida_ua.o_mem
                        and next_insn.ops[0].addr == verify_imp_ea):
                        rva = scan_cursor - get_imagebase()
                        nop_padding = next_insn.size - 5
                        results.extend([
                            f"SingleUserPatch.x64=1",
                            f"SingleUserOffset.x64={rva:X}",
                            f"SingleUserCode.x64=mov_eax_1_nop_{nop_padding}"
                        ])
                        return True

                    if (get_insn_mnemonic(next_insn) == "cmp"
                        and next_insn.size <= 8
                        and next_insn.ops[0].type == ida_ua.o_mem
                        and next_insn.ops[0].specval in (get_reg_id("rbp"), get_reg_id("rsp"))
                        and (
                            (next_insn.ops[1].type == ida_ua.o_imm and next_insn.ops[1].value == 1)
                            or next_insn.ops[1].type == ida_ua.o_reg
                        )):
                        rva = scan_cursor - get_imagebase()
                        results.extend([
                            f"SingleUserPatch.x64=1",
                            f"SingleUserOffset.x64={rva:X}",
                            f"SingleUserCode.x64=nop_{next_insn.size}"
                        ])
                        return True

                else:
                    if (get_insn_mnemonic(next_insn) == "call"
                        and 5 <= next_insn.size <= 7
                        and next_insn.ops[0].type == ida_ua.o_mem
                        and next_insn.ops[0].addr == verify_imp_ea):
                        rva = scan_cursor - get_imagebase()
                        nop_padding = next_insn.size - 4
                        results.extend([
                            f"SingleUserPatch.x86=1",
                            f"SingleUserOffset.x86={rva:X}",
                            f"SingleUserCode.x86=pop_eax_add_esp_12_nop_{nop_padding}"
                        ])
                        return True

                    if (get_insn_mnemonic(next_insn) == "cmp"
                        and next_insn.size <= 8
                        and next_insn.ops[0].type == ida_ua.o_mem
                        and next_insn.ops[0].specval == get_reg_id("ebp")
                        and next_insn.ops[1].type == ida_ua.o_imm
                        and next_insn.ops[1].value == 1):
                        rva = scan_cursor - get_imagebase()
                        results.extend([
                            f"SingleUserPatch.x86=1",
                            f"SingleUserOffset.x86={rva:X}",
                            f"SingleUserCode.x86=nop_{next_insn.size}"
                        ])
                        return True

                scan_cursor += next_insn.size
        return False

    primary_ea = find_func_ea("*CSessionArbitrationHelper::IsSingleSessionPerUserEnabled*")
    if primary_ea and try_scan_in_function(primary_ea, "CSessionArbitrationHelper::IsSingleSessionPerUserEnabled"):
        return results

    fallback_ea = find_func_ea("*CUtils::IsSingleSessionPerUser*")
    if fallback_ea and try_scan_in_function(fallback_ea, "CUtils::IsSingleSessionPerUser"):
        return results

    results.append("ERROR: SingleUserPatch pattern not found")
    return results

def patch_DefPolicy():
    """Modified to return results instead of printing directly"""
    arch = get_arch()
    is_64 = (arch == "x64")
    func_ea = find_func_ea("*CDefPolicy::Query*")
    if func_ea is None:
        return ["ERROR: CDefPolicy::Query not found"]

    debug_log(f"[DefPolicyPatch] Start ({arch})")
    results = []
    
    last_ea = None
    mov_base = None
    mov_target = None
    
    for ea in idautils.FuncItems(func_ea):
        insn = decode_inst(ea)
        if not insn:
            last_ea = ea
            continue
            
        disasm_line = idaapi.tag_remove(idaapi.generate_disasm_line(ea, 0))
        debug_log(f"[DefPolicyPatch] [0x{ea:X}] {disasm_line}")
        mnem = get_insn_mnemonic(insn)
        insn_length = insn.size
        
        if mnem == "cmp":
            op0, op1 = insn.ops[0], insn.ops[1]
            matched = False
            reg1_name = "unknown"
            reg2_name = "global"
            
            if is_64:
                if op0.type == ida_ua.o_displ and op1.type == ida_ua.o_reg and op0.addr == 0x63c:
                    reg1_name = idaapi.get_reg_name(op1.reg, 4) or "reg1"
                    reg2_name = idaapi.get_reg_name(op0.reg, 8) or "reg2"
                    matched = True
                elif op0.type == ida_ua.o_reg and op1.type == ida_ua.o_displ and op1.addr == 0x63c:
                    reg1_name = idaapi.get_reg_name(op0.reg, 4) or "reg1"
                    reg2_name = idaapi.get_reg_name(op1.reg, 8) or "reg2"
                    matched = True
            else:
                if op0.type == ida_ua.o_reg and op1.type == ida_ua.o_displ and op1.addr == 0x320:
                    reg1_name = idaapi.get_reg_name(op0.reg, 4) or "reg1"
                    reg2_name = idaapi.get_reg_name(op1.reg, 4) or "reg2"
                    matched = True
            
            if matched:
                next_ea = ea + insn_length
                next_insn = decode_inst(next_ea)
                suffix = ""
                use_last_ea = False
                if next_insn:
                    next_mnem = get_insn_mnemonic(next_insn)
                    if next_mnem == "jnz":
                        use_last_ea = True
                        suffix = "_jmp"
                    elif next_mnem not in ("jz", "pop"):
                        matched = False
                
                if matched:
                    output_ea = last_ea if use_last_ea else ea
                    rva = output_ea - get_imagebase() if output_ea else 0
                    results.extend([
                        f"DefPolicyPatch.{arch}=1",
                        f"DefPolicyOffset.{arch}={rva:X}",
                        f"DefPolicyCode.{arch}=CDefPolicy_Query_{reg1_name}_{reg2_name}{suffix}"
                    ])
                    return results
        
        elif is_64 and not mov_base and mnem == "mov":
            op0, op1 = insn.ops[0], insn.ops[1]
            if op0.type == ida_ua.o_reg and op1.type == ida_ua.o_displ and op1.addr == 0x63c:
                mov_base = op1.reg
                mov_target = op0.reg
        
        elif is_64 and mov_base and mnem == "mov":
            op0, op1 = insn.ops[0], insn.ops[1]
            if op0.type == ida_ua.o_reg and op1.type == ida_ua.o_displ and op1.reg == mov_base and op1.addr == 0x638:
                mov_target2 = op0.reg
                reg1_name = idaapi.get_reg_name(mov_target2, 4) or "reg1"
                reg2_name = idaapi.get_reg_name(op1.reg, 8) or "reg2"
                
                offset = insn_length
                scan_ea = ea + offset
                cmp_found = False
                cmp_ea = None
                while True:
                    scan_insn = decode_inst(scan_ea)
                    if not scan_insn:
                        break
                    scan_mnem = get_insn_mnemonic(scan_insn)
                    if scan_mnem == "cmp":
                        scan_op0, scan_op1 = scan_insn.ops[0], scan_insn.ops[1]
                        if scan_op0.type == ida_ua.o_reg and scan_op1.type == ida_ua.o_reg:
                            match1 = (scan_op0.reg == mov_target and scan_op1.reg == mov_target2)
                            match2 = (scan_op0.reg == mov_target2 and scan_op1.reg == mov_target)
                            if match1 or match2:
                                cmp_found = True
                                cmp_ea = scan_ea
                                break
                    offset += scan_insn.size
                    scan_ea += scan_insn.size
                
                if cmp_found:
                    post_cmp_ea = cmp_ea + decode_inst(cmp_ea).size
                    post_cmp_insn = decode_inst(post_cmp_ea)
                    suffix = ""
                    use_last_ea = False
                    if post_cmp_insn:
                        post_mnem = get_insn_mnemonic(post_cmp_insn)
                        if post_mnem == "jnz":
                            use_last_ea = True
                            suffix = "_jmp"
                    output_ea = last_ea if use_last_ea else cmp_ea
                    rva = output_ea - get_imagebase() if output_ea else 0
                    results.extend([
                        f"DefPolicyPatch.x64=1",
                        f"DefPolicyOffset.x64={rva:X}",
                        f"DefPolicyCode.x64=CDefPolicy_Query_{reg1_name}_{reg2_name}{suffix}"
                    ])
                    return results
        
        last_ea = ea

    results.append("ERROR: DefPolicyPatch pattern not found")
    return results

def patch_LocalOnly():
    """Modified to return results instead of printing directly"""
    arch = get_arch()
    debug_log(f"[LocalOnlyPatch] Start ({arch})")
    results = []
    
    func1_ea = find_func_ea("*CEnforcementCore::GetInstanceOfTSLicense(*)")
    func2_ea = find_func_ea("*CSLQuery::IsLicenseTypeLocalOnly*")
    if func1_ea is None or func2_ea is None:
        results.append("ERROR: LocalOnly functions not found")
        return results

    image_base = get_imagebase()
    for ea in idautils.FuncItems(func1_ea):
        insn = decode_inst(ea)
        if not insn or get_insn_mnemonic(insn) != "call":
            continue

        called_ea = idaapi.BADADDR
        op = insn.ops[0]
        if op.type == ida_ua.o_near:
            called_ea = op.addr
        if called_ea != func2_ea:
            continue

        ip = ea + insn.size
        mov_count = 0
        while mov_count < 20:
            next_insn = decode_inst(ip)
            if not next_insn or get_insn_mnemonic(next_insn) != "mov":
                break
            ip += next_insn.size
            mov_count += 1

        test_insn = decode_inst(ip)
        if not test_insn or get_insn_mnemonic(test_insn) != "test":
            continue
        ip += test_insn.size

        jmp_insn = decode_inst(ip)
        if not jmp_insn:
            continue
        mnem = get_insn_mnemonic(jmp_insn)
        if mnem not in ("js", "jns") or jmp_insn.ops[0].type != ida_ua.o_near:
            continue
        target = jmp_insn.ops[0].addr
        ip += jmp_insn.size

        cmp_insn = decode_inst(ip)
        if not cmp_insn or get_insn_mnemonic(cmp_insn) != "cmp":
            continue
        ip += cmp_insn.size

        jz_insn = decode_inst(ip)
        if not jz_insn or get_insn_mnemonic(jz_insn) != "jz":
            continue
        if jz_insn.ops[0].type != ida_ua.o_near:
            continue
        jz_target = jz_insn.ops[0].addr

        if jz_target != target:
            continue

        rva = ip - image_base
        code_name = "jmpshort" if jz_insn.size == 2 else "nopjmp"
        debug_log(f"[LocalOnlyPatch] SUCCESS! RVA=0x{rva:X}, code={code_name}")
        results.extend([
            f"LocalOnlyPatch.{arch}=1",
            f"LocalOnlyOffset.{arch}={rva:X}",
            f"LocalOnlyCode.{arch}={code_name}"
        ])
        return results

    results.append("ERROR: LocalOnlyPatch pattern not found")
    return results

def find_var_ea(pattern: str):
    """Find global variable by mangled name pattern."""
    debug_log(f"Search variable: {pattern}")
    for addr, name in idautils.Names():
        if not name:
            continue
        demangled_name = idc.demangle_name(name, idc.INF_SHORT_DN)
        if not demangled_name:
            continue
        if fnmatch.fnmatch(demangled_name.lower(), f"*{pattern.lower()}*"):
            debug_log(f"  -> Match: {name} @ 0x{addr:X}")
            return addr
    debug_log(f"  -> Not found")
    return None

def save_results_to_ini(version_str, results_lines):
    """
    Save analysis results to an .ini file with embedded template.
    Folder path is selected by user via tkinter dialog.
    """
    try:
        try:
            import tkinter as tk
            from tkinter import filedialog
            
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)
            
            folder_path = filedialog.askdirectory(
                title="Select folder to save .ini file",
                initialdir=os.getcwd()
            )
            
            root.destroy()
            
            if not folder_path:
                print("Save cancelled by user.")
                return
                
        except ImportError:
            folder_path = "autogenerated"
            debug_log("tkinter not available, using default folder")
        
        filename = f"{version_str}-autogenerated_{get_arch()}.ini"
        save_path = os.path.join(folder_path, filename)
        
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        current_date = datetime.datetime.now().strftime("%Y-%m-%d")
        updated_template = INI_TEMPLATE.replace("Updated=2021-06-23", f"Updated={current_date}")
        
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(updated_template)
            
            for line in results_lines:
                f.write(line + '\n')
        
        print(f"Results saved to: {save_path}")
        debug_log(f"Successfully saved results to {save_path}")
    except Exception as e:
        print(f"ERROR: Failed to save results to file: {e}")
        debug_log(f"Exception in save_results_to_ini: {e}")

def analyze_termsrv():
    ver = get_file_version()
    arch = get_arch()
    version_header = f"[{ver[0]}.{ver[1]}.{ver[2]}.{ver[3]}]"
    print(version_header)
    debug_log(f"Analyze termsrv.dll (ver: {ver[0]}.{ver[1]}.{ver[2]}.{ver[3]}, arch: {arch})")
    
    results_lines = [version_header]
    
    if (ver[0] == 6 and ver[1] >= 3) or ver[0] >= 10:
        localonly_results = patch_LocalOnly()
        results_lines.extend(localonly_results)
        for line in localonly_results:
            print(line)
    
    singleuser_results = patch_SingleUser()
    results_lines.extend(singleuser_results)
    for line in singleuser_results:
        print(line)
        
    defpolicy_results = patch_DefPolicy()
    results_lines.extend(defpolicy_results)
    for line in defpolicy_results:
        print(line)
    
    if ver[0] == 6 and ver[1] == 2:
        sl_ea = find_func_ea("*SLGetWindowsInformationDWORDWrapper*")
        if sl_ea is not None:
            rva = sl_ea - get_imagebase()
            if check_SLPolicyCP(sl_ea):
                sl_lines = [
                    f"SLPolicyInternal.{arch}=1",
                    f"SLPolicyOffset.{arch}={rva:X}",
                    f"SLPolicyFunc.{arch}=New_Win8SL_CP"
                ]
            else:
                sl_lines = [
                    f"SLPolicyInternal.{arch}=1",
                    f"SLPolicyOffset.{arch}={rva:X}",
                    f"SLPolicyFunc.{arch}=New_Win8SL"
                ]
            results_lines.extend(sl_lines)
            for line in sl_lines:
                print(line)
        else:
            error_msg = "ERROR: SLGetWindowsInformationDWORDWrapper not found"
            results_lines.append(error_msg)
            print(error_msg)
        save_results_to_ini(f"{ver[0]}.{ver[1]}.{ver[2]}.{ver[3]}", results_lines)
        return
    
    if (ver[0] == 6 and ver[1] >= 3) or ver[0] >= 10:
        init_ea = find_func_ea("*CSLQuery::Initialize*")
        if init_ea is not None:
            rva = init_ea - get_imagebase()
            slinit_lines = [
                f"SLInitHook.{arch}=1",
                f"SLInitOffset.{arch}={rva:X}",
                f"SLInitFunc.{arch}=New_CSLQuery_Initialize"
            ]
            results_lines.extend(slinit_lines)
            for line in slinit_lines:
                print(line)

            slinit_section = [
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
                ""
            ]
            results_lines.extend(slinit_section)
            
            print("")

            slinit_header = f"[{ver[0]}.{ver[1]}.{ver[2]}.{ver[3]}-SLInit]"
            results_lines.append(slinit_header)
            print(slinit_header)
            
            vars_ordered = [
                "bInitialized",
                "bServerSku", 
                "lMaxUserSessions",
                "bAppServerAllowed",
                "bRemoteConnAllowed",
                "bMultimonAllowed",
                "ulMaxDebugSessions",
                "bFUSEnabled"
            ]
            
            var_addresses = {}
            for var in vars_ordered:
                var_ea = find_var_ea(f"*CSLQuery::{var}*")
                if var_ea is not None:
                    var_addresses[var] = var_ea - get_imagebase()
                else:
                    var_addresses[var] = None
            
            max_var_len = max(len(var) for var in vars_ordered)
            for var in vars_ordered:
                if var_addresses[var] is not None:
                    line = f"{var}.{arch}".ljust(max_var_len + len(arch) + 1) + f"={var_addresses[var]:X}"
                    results_lines.append(line)
                    print(line)
                else:
                    error_msg = f"ERROR: {var} not found"
                    results_lines.append(error_msg)
                    print(error_msg)
        else:
            error_msg = "ERROR: CSLQuery_Initialize not found"
            results_lines.append(error_msg)
            print(error_msg)
    
    save_results_to_ini(f"{ver[0]}.{ver[1]}.{ver[2]}.{ver[3]}", results_lines)

class TermsrvPatchPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Locate patch points in termsrv.dll for RDP multi-session"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl+Alt+R"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        analyze_termsrv()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return TermsrvPatchPlugin()