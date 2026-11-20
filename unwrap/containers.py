"""The files scripts arrive in: Windows shortcuts (.lnk, the most common first stage today) and HTML
applications or pages (.hta, .html: script blocks, HTML smuggling). A container is read, never opened:
its command line or scripts become layer 0, and what the container itself gives away (padded arguments,
a borrowed icon, a hidden window, the machine that built it) is reported next to the layers."""

from __future__ import annotations

import ntpath
import re
import struct
from dataclasses import dataclass, field

LNK_HEADER = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
SHOW = {1: "normal", 3: "maximized", 7: "minimized, not activated"}
INTERPRETERS = {"powershell.exe": "powershell", "pwsh.exe": "powershell", "cmd.exe": "batch", "wscript.exe": None,
                "cscript.exe": None, "mshta.exe": None, "rundll32.exe": None, "regsvr32.exe": None, "msiexec.exe": None,
                "conhost.exe": None, "forfiles.exe": None, "certutil.exe": None, "bitsadmin.exe": None, "curl.exe": None,
                "explorer.exe": None, "wmic.exe": None, "schtasks.exe": None, "hh.exe": None, "msbuild.exe": None}
VISIBLE_ARGS = 260                     # what the shortcut's Properties dialog shows of the arguments


@dataclass
class Container:
    kind: str                                   # "lnk", "hta", "html"
    text: str                                   # what becomes layer 0
    language: str | None = None
    fields: dict[str, str] = field(default_factory=dict)
    findings: list[tuple[str, str, str]] = field(default_factory=list)   # (technique, description, evidence)


# ── shortcuts (MS-SHLLINK) ───────────────────────────────────────────────────

def _cstr(b: bytes, pos: int, wide: bool) -> str:
    if wide:
        end = pos
        while end + 1 < len(b) and b[end:end + 2] != b"\0\0":
            end += 2
        return b[pos:end].decode("utf-16-le", "replace")
    end = b.find(b"\0", pos)
    return b[pos:end if end >= 0 else len(b)].decode("cp1252", "replace")


def _idlist_path(items: bytes) -> str:
    """Best-effort path from shell items: drive letter, then each file entry's long name."""
    parts, i = [], 0
    while i + 2 <= len(items) and len(parts) < 64:
        size = struct.unpack_from("<H", items, i)[0]
        if size < 3:
            break
        item = items[i:i + size]
        kind = item[2] & 0x70
        if item[2] == 0x2F and len(item) > 5:                         # volume: "C:\"
            parts = [item[3:5].decode("ascii", "replace")]
        elif kind == 0x30 and len(item) > 14:                         # file entry: 8.3 name, then a long one
            short = _cstr(item, 14, False)
            long_names = re.findall(rb"(?:[\x20-\x7e]\x00){2,}(?=\x00\x00)", item[14 + len(short):])
            parts.append(long_names[-1].decode("utf-16-le") if long_names else short)
        i += size
    return "\\".join(parts).replace(":\\\\", ":\\") if parts else ""


def read_lnk(data: bytes) -> Container:
    if len(data) < 0x4C or data[:20] != LNK_HEADER:
        raise ValueError("not a Windows shortcut")
    flags = struct.unpack_from("<I", data, 0x14)[0]
    show = struct.unpack_from("<I", data, 0x3C)[0]
    wide = bool(flags & 0x80)
    pos, target = 0x4C, ""
    if flags & 0x01:                                                  # LinkTargetIDList
        size = struct.unpack_from("<H", data, pos)[0]
        target = _idlist_path(data[pos + 2:pos + 2 + size])
        pos += 2 + size
    if flags & 0x02:                                                  # LinkInfo
        info = data[pos:pos + struct.unpack_from("<I", data, pos)[0]]
        if len(info) >= 0x1C:
            hdr, lflags, _, base = struct.unpack_from("<IIII", info, 4)
            if hdr >= 0x24 and len(info) >= 0x24 and struct.unpack_from("<I", info, 0x1C)[0]:
                target = _cstr(info, struct.unpack_from("<I", info, 0x1C)[0], True) or target
            elif lflags & 1 and base:
                target = _cstr(info, base, False) or target
        pos += len(info)
    strings = {}
    for bit, name in ((0x04, "name"), (0x08, "relative path"), (0x10, "working dir"), (0x20, "arguments"),
                      (0x40, "icon")):
        if flags & bit and pos + 2 <= len(data):
            n = struct.unpack_from("<H", data, pos)[0]
            raw = data[pos + 2:pos + 2 + n * (2 if wide else 1)]
            strings[name] = raw.decode("utf-16-le" if wide else "cp1252", "replace")
            pos += 2 + len(raw)
    machine = ""
    while pos + 8 <= len(data):                                       # extra data blocks
        size, sig = struct.unpack_from("<II", data, pos)
        if size < 8:
            break
        block = data[pos:pos + size]
        if sig == 0xA0000001 and len(block) >= 0x314 and not target:  # environment-variable target
            target = _cstr(block, 0x10C, True) or _cstr(block, 8, False)
        elif sig == 0xA0000003 and len(block) >= 0x20:                # tracker: the NetBIOS name of the machine it was made on
            machine = _cstr(block, 16, False)[:16]
        pos += size

    args = strings.get("arguments", "")
    exe = ntpath.basename(target).lower()
    c = Container("lnk", f"{target} {args}".strip() if target else args, INTERPRETERS.get(exe))
    c.fields = {"target": target or "(not recorded)", "arguments": f"{len(args):,} chars" if args else "none",
                "working dir": strings.get("working dir", ""), "icon": strings.get("icon", ""),
                "window": SHOW.get(show, f"code {show}"), "built on": machine}
    c.fields = {k: v for k, v in c.fields.items() if v}
    stripped = args.lstrip()
    if len(args) > VISIBLE_ARGS and (len(args) - len(stripped) >= 32 or re.search(r"\s{64,}", args)):
        c.findings.append(("T1027", "pads its arguments so the shortcut's Properties dialog shows only blanks",
                           f"{len(args) - len(stripped):,} leading blank characters before {stripped[:40]!r}"))
    elif len(args) > VISIBLE_ARGS:
        c.findings.append(("T1027", "has arguments longer than the Properties dialog shows",
                           f"{len(args):,} characters"))
    if exe in INTERPRETERS:
        c.findings.append(("T1204.002", f"is a shortcut that starts {exe}", target))
        icon = strings.get("icon", "").lower()
        if icon and exe not in icon:
            c.findings.append(("T1036", "borrows another program's icon to look like a document or folder",
                               strings.get("icon", "")))
    if show == 7:
        c.findings.append(("T1564.003", "starts minimized without taking focus", "ShowCommand = 7"))
    return c


# ── HTML applications and pages ──────────────────────────────────────────────

SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.S | re.I)
LANG = re.compile(r"""\b(?:language|type)\s*=\s*["']?(?:text/)?([\w.-]+)""", re.I)


def read_html(text: str, hta: bool) -> Container | None:
    blocks: dict[str, list[str]] = {}
    for attrs, body in SCRIPT.findall(text):
        if not body.strip() or re.search(r"\bsrc\s*=", attrs, re.I):
            continue
        m = LANG.search(attrs)
        lang = (m.group(1).lower() if m else "javascript")
        lang = "vbscript" if lang.startswith("vbs") else "javascript"
        blocks.setdefault(lang, []).append(body.strip())
    if not blocks:
        return None
    lang = max(blocks, key=lambda k: sum(map(len, blocks[k])))
    c = Container("hta" if hta else "html", "\n".join(blocks[lang]), lang)
    c.fields = {"scripts": ", ".join(f"{len(v)} {k}" for k, v in blocks.items())}
    if len(blocks) > 1:
        c.fields["note"] = f"unwrapping the {lang} blocks; the others are listed in the scripts field"
    if hta:
        c.findings.append(("T1218.005", "is an HTML application: mshta.exe runs it with full user rights", "HTA"))
    joined = "\n".join(sum(blocks.values(), []))
    if re.search(r"\bnew\s+Blob\s*\(", joined) and re.search(r"\.download\s*=|msSaveOrOpenBlob|msSaveBlob", joined):
        c.findings.append(("T1027.006", "smuggles a file: builds it in the browser and hands it over as a download",
                           re.search(r"[^\n;]*\bnew\s+Blob\s*\([^\n;]*", joined).group(0).strip()[:90]))
    return c


def open_container(raw: bytes, name: str = "") -> Container | None:
    """The container in `raw`, if it is one; None for a plain script."""
    if raw[:20] == LNK_HEADER:
        try:
            return read_lnk(raw)
        except (struct.error, IndexError) as e:
            raise ValueError(f"damaged shortcut ({e})") from None
    head = raw[:4096].decode("utf-8", "replace").lower()
    hta = name.lower().endswith(".hta") or "<hta:application" in head
    if hta or name.lower().endswith((".html", ".htm", ".xhtml", ".svg")) or re.search(r"<(?:!doctype html|html|script)\b", head):
        return read_html(raw.decode("utf-8", "replace"), hta)
    return None
