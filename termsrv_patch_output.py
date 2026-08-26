# -*- coding: utf-8 -*-
"""Formatting helpers for generated RDP Wrapper version sections."""

from typing import Dict, Iterable, List, Optional, Sequence


SLINIT_ORDER = (
    "bInitialized",
    "bServerSku",
    "lMaxUserSessions",
    "bAppServerAllowed",
    "bRemoteConnAllowed",
    "bMultimonAllowed",
    "ulMaxDebugSessions",
    "bFUSEnabled",
)


def format_patch_block(name: str, arch: str, values: Sequence[str]) -> List[str]:
    if values and values[0].startswith("ERROR:"):
        return list(values)

    value_map = dict(line.split("=", 1) for line in values if "=" in line)
    return [
        f"{name}Patch.{arch}={value_map[f'{name}Patch.{arch}']}",
        f"{name}Offset.{arch}={value_map[f'{name}Offset.{arch}']}",
        f"{name}Code.{arch}={value_map[f'{name}Code.{arch}']}",
    ]


def format_slinit_hook(arch: str, offset: int) -> List[str]:
    return [
        f"SLInitHook.{arch}=1",
        f"SLInitOffset.{arch}={offset:X}",
        f"SLInitFunc.{arch}=New_CSLQuery_Initialize",
    ]


def format_slinit_section(
    version: str, arch: str, addresses: Dict[str, Optional[int]]
) -> List[str]:
    key_width = max(len(f"{name}.{arch}") for name in SLINIT_ORDER)
    lines = [f"[{version}-SLInit]"]
    for name in SLINIT_ORDER:
        address = addresses.get(name)
        if address is None:
            lines.append(f"ERROR: {name} not found")
            continue
        lines.append(f"{name}.{arch}".ljust(key_width) + f"={address:X}")
    return lines


def join_blocks(blocks: Iterable[Sequence[str]]) -> List[str]:
    output: List[str] = []
    for block in blocks:
        output.extend(block)
    return output
