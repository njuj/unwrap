"""The other direction: wrap a harmless payload in the obfuscation techniques real droppers use.

Tests feed the result to unwrap and demand the exact payload back. Every technique is code -> code, so
they stack in any order (Invoke-Obfuscation-style token tricks, Base64, gzip, XOR, packers ...).
Payloads are harmless on purpose; nothing here is ever run.
"""

from __future__ import annotations

import base64
import random
import re
import zlib

from unwrap.literals import js_render, ps_render, vbs_render

def _junk(rng: random.Random, code: str) -> tuple[str, str]:
    """Sprinkle a marker through the code. Like real droppers, pick one the code cannot be confused with:
    removing it (case-insensitively, as PowerShell's -replace does) must give back exactly the code."""
    while True:
        marker = "".join(rng.choice("QXZJKVW") for _ in range(rng.randint(3, 6)))
        junked = "".join(c + (marker if rng.random() < 0.3 else "") for c in code)
        if marker.lower() not in code.lower() and re.sub(marker, "", junked, flags=re.I) == code:
            return marker, junked


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _chunks(rng: random.Random, s: str, parts: int) -> list[str]:
    if len(s) < 2:
        return [s]
    cuts = sorted(rng.sample(range(1, len(s)), min(parts - 1, len(s) - 1)))
    return [s[a:b] for a, b in zip([0] + cuts, cuts + [len(s)])]


def _tick(rng: random.Random, word: str) -> str:
    """Invoke-Obfuscation's tick trick, never before a letter that is a real escape (`n, `t, ...)."""
    return "".join(("`" + ch) if ch.isalpha() and ch.lower() not in "0abefnrtuv" and rng.random() < 0.5 else ch
                   for ch in word)


def _case(rng: random.Random, s: str) -> str:
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in s)


def _iex_spelled(rng: random.Random) -> str:
    """The IEX spellings Invoke-Obfuscation's launchers use: characters picked out of well-known variables."""
    return _case(rng, rng.choice([
        "( $ShellId[1]+$ShellId[13]+'x')",
        f"( $PSHome[{rng.choice([4, 21])}]+$PSHome[{rng.choice([30, 34])}]+'x')",
        "( $env:Public[13]+$env:Public[5]+'x')",
        f"( $env:ComSpec[4,{rng.choice([15, 24, 26])},25]-Join'')",
        f"(({rng.choice(['Get-Variable', 'GV', 'Variable'])} '*mdr*').Name[3,11,2]-Join'')",
        f"( {rng.choice(['$VerbosePreference.ToString()', '([String]$VerbosePreference)'])}[1,3]+'x'-Join'')",
    ]))


def _invoke(rng: random.Random, expr: str) -> str:
    style = rng.randrange(8)
    if style == 0:
        return f"iex ({expr})"
    if style == 1:
        return f"Invoke-Expression ({expr})"
    if style == 2:
        return f"{_tick(rng, 'Invoke-Expression')} ({expr})"
    if style == 3:
        return f"&('IEX') ({expr})"
    if style == 4:
        return f"({expr}) | {_tick(rng, 'iex')}"
    if style == 5:
        return f".('iex')({expr})"
    if style == 6:
        return f"{rng.choice('&.')}{_iex_spelled(rng)} ({expr})"
    return f"({expr}) | {rng.choice('&.')}{_iex_spelled(rng)}"


# ── PowerShell ────────────────────────────────────────────────────────────────

def ps_encoded(rng, code):
    return f"powershell.exe -NoP -NonI -W Hidden -{rng.choice(['enc', 'e', 'EncodedCommand', 'ec'])} " + \
        _b64(code.encode("utf-16-le"))


def ps_base64(rng, code):
    codec, encoding = rng.choice([("UTF8", "utf-8"), ("Unicode", "utf-16-le")])
    return _invoke(rng, f"[Text.Encoding]::{codec}.GetString([Convert]::FromBase64String('"
                        f"{_b64(code.encode(encoding))}'))")


def ps_gzip(rng, code):
    if rng.random() < 0.5:
        blob, stream = _b64(_gzip(code.encode())), "IO.Compression.GzipStream"
    else:
        co = zlib.compressobj(9, zlib.DEFLATED, -15)
        blob, stream = _b64(co.compress(code.encode()) + co.flush()), "IO.Compression.DeflateStream"
    return _invoke(rng, f"(New-Object IO.StreamReader((New-Object {stream}([IO.MemoryStream][Convert]::"
                        f"FromBase64String('{blob}'),[IO.Compression.CompressionMode]::Decompress)),"
                        f"[Text.Encoding]::UTF8)).ReadToEnd()")


def _gzip(data: bytes) -> bytes:
    co = zlib.compressobj(9, zlib.DEFLATED, 16 + 15)
    return co.compress(data) + co.flush()


def ps_xor(rng, code):
    key = rng.randrange(1, 255)
    blob = _b64(bytes(b ^ key for b in code.encode()))
    return _invoke(rng, f"-join ([Convert]::FromBase64String('{blob}') | % {{ [char]($_ -bxor 0x{key:02x}) }})")


def ps_concat(rng, code):
    return _invoke(rng, "+".join(ps_render(c) for c in _chunks(rng, code, rng.randint(2, 6))))


def ps_format(rng, code):
    parts = _chunks(rng, code, rng.randint(2, 6))
    order = list(range(len(parts)))
    rng.shuffle(order)                                   # args shuffled, placeholders put them back
    args = [None] * len(parts)
    for slot, i in enumerate(order):
        args[slot] = parts[i]
    fmt = "".join("{%d}" % order.index(i) for i in range(len(parts)))
    return _invoke(rng, f"({ps_render(fmt)} -f {','.join(ps_render(a) for a in args)})")


def ps_reverse(rng, code):
    if rng.random() < 0.5:
        return _invoke(rng, f"{ps_render(code[::-1])}[-1..-{len(code)}] -join ''")
    var = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(6))
    return f"${var}={ps_render(code[::-1])};" + _invoke(rng, f"${var}[-1..-(${var}.Length)] -join ''")


def ps_chars(rng, code):
    nums = ",".join(str(ord(c)) if rng.random() < 0.7 else hex(ord(c)) for c in code)
    style = rng.randrange(3)
    if style == 0:
        return _invoke(rng, f"[char[]]({nums}) -join ''")
    if style == 1:
        return _invoke(rng, f"-join [char[]]({nums})")
    return _invoke(rng, f"({nums}|%{{[char]$_}})-join''")


def ps_replace(rng, code):
    marker, junked = _junk(rng, code)
    if rng.random() < 0.5:
        return _invoke(rng, f"({ps_render(junked)} -replace '{marker}','')")
    return _invoke(rng, f"({ps_render(junked)}.Replace('{marker}',''))")


def ps_vars(rng, code):
    parts = _chunks(rng, code, rng.randint(2, 4))
    names = ["".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(5)) + str(i) for i in range(len(parts))]
    assigns = ";".join(f"${n}={ps_render(p)}" for n, p in zip(names, parts))
    return assigns + ";" + _invoke(rng, "+".join(f"${n}" for n in names))


PS_TECHNIQUES = [ps_encoded, ps_base64, ps_gzip, ps_xor, ps_concat, ps_format, ps_reverse, ps_chars, ps_replace,
                 ps_vars]


# ── JavaScript ────────────────────────────────────────────────────────────────

def _js_exec(rng: random.Random, expr: str, eval_only: bool = False) -> str:
    """Run a string expression as code. (The interpreter tests swap this for a print.)"""
    if eval_only or rng.random() < 0.6:
        return f"eval({expr})"
    return f"{rng.choice(['new Function', 'Function'])}({expr})()"


def js_eval(rng, code):
    return _js_exec(rng, js_render(code))


def js_atob(rng, code):
    return _js_exec(rng, f"atob('{_b64(code.encode('latin-1'))}')")


def js_charcode(rng, code):
    return _js_exec(rng, f"String.fromCharCode({','.join(str(ord(c)) for c in code)})")


def js_unescape(rng, code):
    return _js_exec(rng, "unescape('" + "".join(f"%{ord(c):02X}" if ord(c) < 256 else f"%u{ord(c):04X}"
                                                for c in code) + "')")


def js_hex(rng, code):
    return _js_exec(rng, "'" + "".join(f"\\x{ord(c):02x}" for c in code) + "'")


def js_concat(rng, code):
    return _js_exec(rng, "+".join(js_render(c) for c in _chunks(rng, code, rng.randint(2, 5))))


def js_reverse(rng, code):
    return _js_exec(rng, f"{js_render(code[::-1])}.split('').reverse().join('')")


def _base62(n: int, radix: int) -> str:
    def digit(v):
        return chr(v + 29) if v > 35 else "0123456789abcdefghijklmnopqrstuvwxyz"[v]
    out = ""
    while True:
        out = digit(n % radix) + out
        n //= radix
        if not n:
            return out


def js_packer(rng, code, radix=62):
    words = sorted(set(re.findall(r"\b\w+\b", code)))
    index = {w: i for i, w in enumerate(words)}
    payload = re.sub(r"\b\w+\b", lambda m: _base62(index[m.group(0)], radix), code)
    return _js_exec(rng, "function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?"
                         "String.fromCharCode(c+29):c.toString(36))};if(!''.replace(/^/,String)){while(c--){d[e(c)]="
                         "k[c]||e(c)}k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1};while(c--){if(k[c])"
                         "{p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}(" + js_render(payload) +
                    f",{radix},{len(words)}," + js_render("|".join(words)) + ".split('|'),0,{})", eval_only=True)


JS_TECHNIQUES = [js_eval, js_atob, js_charcode, js_unescape, js_hex, js_concat, js_reverse, js_packer]


# ── VBScript and batch ────────────────────────────────────────────────────────

def _vbs_expr(rng, s: str) -> str:
    """A VBScript string expression for s: a literal cannot hold a line break, so those become vbCrLf / Chr()."""
    parts = []
    for run in re.split(r"(\r\n|[\x00-\x1f])", s):
        if run == "\r\n":
            parts.append(rng.choice(["vbCrLf", "vbNewLine", "Chr(13) & Chr(10)"]))
        elif len(run) == 1 and ord(run) < 32:
            parts.append({"\n": "vbLf", "\t": "vbTab"}.get(run, f"Chr({ord(run)})") if rng.random() < 0.5
                         else f"Chr({ord(run)})")
        elif run:
            parts.append(vbs_render(run))
    return " & ".join(parts) or '""'


def _vbs_exec(rng: random.Random, expr: str) -> str:
    """Run a string expression as code. (The interpreter tests swap this for a print.)"""
    return rng.choice([f"Execute({expr})", f"Execute {expr}", f"ExecuteGlobal({expr})"])


def vbs_chr(rng, code):
    return _vbs_exec(rng, " & ".join(f"Chr({ord(c)})" if rng.random() < 0.6 else f"ChrW(&H{ord(c):X})" for c in code))


def vbs_reverse(rng, code):
    return _vbs_exec(rng, f"StrReverse({_vbs_expr(rng, code[::-1])})")


def vbs_concat(rng, code):
    return _vbs_exec(rng, " & ".join(_vbs_expr(rng, c) for c in _chunks(rng, code, rng.randint(2, 5))))


def vbs_replace(rng, code):
    marker, junked = _junk(rng, code)
    return _vbs_exec(rng, f'Replace({_vbs_expr(rng, junked)}, "{marker}", "")')


VBS_TECHNIQUES = [vbs_chr, vbs_reverse, vbs_concat, vbs_replace]


def batch_launcher(rng, ps_code, verb="call"):
    """cmd-style dropper: split 'powershell' across set variables, sprinkle carets, pass -enc.
    (verb='echo' makes cmd print the command line instead: the interpreter tests use that.)"""
    word = "powershell"
    parts = _chunks(rng, word, 3)
    names = [f"v{i}{rng.randrange(100)}" for i in range(len(parts))]
    lines = ["@echo off"] + [f"set {n}={p}" for n, p in zip(names, parts)]
    call = "".join(f"%{n}%" for n in names)
    flag = "".join(("^" + ch) if rng.random() < 0.4 else ch for ch in "-enc")
    lines.append(f"{verb} {call} -nop -w hidden {flag} {_b64(ps_code.encode('utf-16-le'))}")
    return "\r\n".join(lines)


# Harmless payloads, already in normal form (nothing left for unwrap to fold), with the characters that
# make quoting hard: both quotes, backticks, $, braces, line breaks.
_DL = "Download" + "String"
PAYLOADS = {
    "powershell": [
        "Write-Output 'unwrap-ok'",
        "Get-Date | Out-File -FilePath C:\\Temp\\stamp.txt",
        f"(New-Object Net.WebClient).{_DL}('http://example.com/x.txt') | Out-Null",
        "Write-Host \"it's fine\"; Start-Sleep -Seconds 1",
        "Get-ChildItem -Path . -Filter *.log | Select-Object -First 3",
        "$n = 0\r\nforeach ($i in 1..3) { $n += $i }\r\nWrite-Output \"sum: $n `t{ok}\"",
    ],
    "javascript": [
        "console.log('unwrap-ok');",
        "var u = 'http://example.org/a.js'; WScript.Echo(u);",
        "function f(a, b) { return a + b; } f(1, 2);",
        "var s = \"it's \\\"quoted\\\"\";\nvar t = s.length > 2 ? s : '\\\\';",
    ],
    "vbscript": [
        'WScript.Echo "unwrap-ok"',
        "Dim s: s = Now: WScript.Echo s",
        'Dim s\r\ns = Now\r\nWScript.Echo "t=" & s',
        'If 1 > 0 Then WScript.Echo "say ""hi"""',
    ],
}
TECHNIQUES = {"powershell": PS_TECHNIQUES, "javascript": JS_TECHNIQUES, "vbscript": VBS_TECHNIQUES}


def stack(rng: random.Random, code: str, techniques, depth: int) -> tuple[str, list[str]]:
    used = []
    for _ in range(depth):
        technique = rng.choice(techniques)
        code = technique(rng, code)
        used.append(technique.__name__)
    return code, used
