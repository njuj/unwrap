"""Windows shortcuts written byte by byte from MS-SHLLINK, in memory only: the malicious shapes (padded
arguments, a borrowed icon, a hidden window) never touch the disk, where antivirus rightly quarantines them."""

import struct

from unwrap.containers import LNK_HEADER


def _counted(s: str) -> bytes:
    return struct.pack("<H", len(s)) + s.encode("utf-16-le")


def _link_info(path: str) -> bytes:
    volume = struct.pack("<IIII", 0x11, 3, 0x1234ABCD, 0x10) + b"\0"
    base = path.encode("cp1252") + b"\0"
    head = 0x1C
    return struct.pack("<IIIIIII", head + len(volume) + len(base) + 1, head, 1, head, head + len(volume), 0,
                       head + len(volume) + len(base)) + volume + base + b"\0"


def _file_item(short: str, long: str, folder: bool) -> bytes:
    name = short.encode("ascii") + b"\0"
    if len(name) % 2:
        name += b"\0"
    ext = struct.pack("<HHI", 0, 9, 0xBEEF0004) + b"\0" * 8 + long.encode("utf-16-le") + b"\0\0" + b"\0\0"
    ext = struct.pack("<H", len(ext)) + ext[2:]
    body = bytes([0x31 if folder else 0x32, 0]) + struct.pack("<IIH", 0, 0, 0x10 if folder else 0x20) + name + ext
    return struct.pack("<H", len(body) + 2) + body


def _idlist(path: str) -> bytes:
    drive, *rest = path.split("\\")
    items = struct.pack("<H", 20) + b"\x1f\x50" + bytes.fromhex("e04fd020ea3a6910a2d808002b30309d")   # My Computer
    vol = b"\x2f" + (drive + "\\").encode("ascii").ljust(22, b"\0")
    items += struct.pack("<H", len(vol) + 2) + vol
    for i, part in enumerate(rest):
        items += _file_item(part.upper()[:12], part, i < len(rest) - 1)
    items += b"\0\0"
    return struct.pack("<H", len(items)) + items


def make_lnk(target: str, arguments: str = "", icon: str = "", show: int = 1, workdir: str = "",
             machine: str = "", idlist_only: bool = False) -> bytes:
    flags = 0x80 | (0x01 if idlist_only else 0x02)
    flags |= (0x10 if workdir else 0) | (0x20 if arguments else 0) | (0x40 if icon else 0)
    header = LNK_HEADER + struct.pack("<II", flags, 0x20) + b"\0" * 24 + struct.pack("<IiI", 0, 0, show) + b"\0" * 12
    assert len(header) == 0x4C
    out = header + (_idlist(target) if idlist_only else _link_info(target))
    for s in (workdir, arguments, icon):
        if s:
            out += _counted(s)
    if machine:
        out += struct.pack("<IIII", 0x60, 0xA0000003, 0x58, 0) + machine.encode("ascii").ljust(16, b"\0") + b"\0" * 64
    return out + b"\0\0\0\0"
