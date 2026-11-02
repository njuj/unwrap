"""Differential test: the real interpreters agree with the obfuscator.

The round-trip tests prove unwrap recovers whatever the obfuscator produces. These prove the obfuscator
produces what PowerShell, Node.js, cscript and cmd actually compute, so the round trip is not a closed
loop: every sample is genuine obfuscation.

Only the string-building half runs. The "execute it" wrapper (iex, eval, Execute, call) is swapped for
a print, so the interpreter computes the hidden code and hands it back as data; the payloads (harmless
anyway) are never run. Each test skips when its interpreter is not installed.
"""

import base64
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import obfuscator as ob

SEEDS = 12                                   # per technique and payload


def _cases(lang, techniques=None):
    cases = []
    for technique in techniques or ob.TECHNIQUES[lang]:
        for i, payload in enumerate(ob.PAYLOADS[lang]):
            for seed in range(SEEDS):
                rng = random.Random(f"{technique.__name__}/{i}/{seed}")
                cases.append((technique.__name__, payload, technique(rng, payload)))
    return cases


def _run(argv, script, suffix, encoding="utf-8"):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "cases" + suffix)
        with open(path, "w", encoding=encoding, newline="") as f:
            f.write(script)
        out = subprocess.run(argv + [path], capture_output=True, timeout=600)
    return out.stdout.decode("utf-8", "replace").splitlines()


class Interpreters(unittest.TestCase):
    def check(self, cases, got):
        self.assertEqual(len(got), len(cases), "the interpreter did not answer every case")
        bad = [(name, payload, code[:120], answer[:120]) for (name, payload, code), answer in zip(cases, got)
               if answer != payload]
        self.assertEqual(bad, [], f"{len(bad)} of {len(cases)} cases disagree with the interpreter")

    @unittest.skipUnless(shutil.which("powershell") or shutil.which("pwsh"), "PowerShell not installed")
    def test_powershell(self):
        with mock.patch.object(ob, "_invoke", lambda rng, expr: f"({expr})"):
            cases = _cases("powershell", [t for t in ob.PS_TECHNIQUES if t is not ob.ps_encoded])
        # -EncodedCommand: what powershell.exe itself decodes the argument to
        for i, payload in enumerate(ob.PAYLOADS["powershell"]):
            blob = ob.ps_encoded(random.Random(i), payload).split()[-1]
            cases.append(("ps_encoded", payload, f"[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("
                                                 f"'{blob}'))"))
        lines = [f"try {{ $v = & {{ {code} }}; [Console]::Out.WriteLine([Convert]::ToBase64String("
                 f"[Text.Encoding]::UTF8.GetBytes([string]$v))) }} catch {{ [Console]::Out.WriteLine('ERR') }}"
                 for _, _, code in cases]
        exe = shutil.which("powershell") or shutil.which("pwsh")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cases.txt")
            with open(path, "w", encoding="utf-8-sig", newline="") as f:     # payload line breaks stay as they are
                f.write("\r\n".join(lines) + "\r\n")
            # a script block built from the file: no .ps1 is run, so no execution policy is involved
            out = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command",
                                  f"& ([ScriptBlock]::Create([IO.File]::ReadAllText('{path}')))"],
                                 capture_output=True, timeout=600)
        got = [base64.b64decode(x).decode("utf-8") if x != "ERR" else "ERR"
               for x in out.stdout.decode("ascii", "replace").split()]
        self.check(cases, got)

    @unittest.skipUnless(sys.platform == "win32" and shutil.which("powershell"), "needs Windows PowerShell")
    def test_powershell_iex_spellings(self):
        """Invoke-Obfuscation's IEX spellings, evaluated on a real Windows box, all spell iex."""
        spellings = sorted({ob._iex_spelled(random.Random(seed)) for seed in range(400)})
        script = "\n".join(f"[Console]::Out.WriteLine({s})" for s in spellings) + "\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cases.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write(script)
            out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                  f"& ([ScriptBlock]::Create([IO.File]::ReadAllText('{path}')))"],
                                 capture_output=True, timeout=120)
        got = out.stdout.decode("ascii", "replace").split()
        self.assertEqual(len(got), len(spellings))
        self.assertEqual({g.lower() for g in got}, {"iex"}, dict(zip(spellings, got)))

    @unittest.skipUnless(shutil.which("node"), "Node.js not installed")
    def test_javascript(self):
        with mock.patch.object(ob, "_js_exec", lambda rng, expr, eval_only=False: f"({expr})"):
            cases = _cases("javascript")
        script = "".join("try { console.log(Buffer.from(String(" + code + "), 'utf8').toString('base64')) } "
                         "catch (e) { console.log('ERR') }\n" for _, _, code in cases)
        got = [base64.b64decode(x).decode("utf-8") if x != "ERR" else "ERR"
               for x in _run(["node"], script, ".js")]
        self.check(cases, got)

    @unittest.skipUnless(sys.platform == "win32" and shutil.which("cscript"), "needs Windows Script Host")
    def test_vbscript(self):
        with mock.patch.object(ob, "_vbs_exec", lambda rng, expr: f"({expr})"):
            cases = _cases("vbscript")
        script = ["Function Hx(s)", "  Dim i, r: r = \"\"",
                  "  For i = 1 To Len(s): r = r & Right(\"000\" & Hex(AscW(Mid(s, i, 1))), 4): Next",
                  "  Hx = r & \"-\"", "End Function"]
        script += [f"WScript.StdOut.WriteLine Hx({code})" for _, _, code in cases]
        lines = _run(["cscript", "//nologo", "//E:vbscript"], "\r\n".join(script) + "\r\n", ".vbs", "cp1252")
        got = ["".join(chr(int(h[i:i + 4], 16)) for i in range(0, len(h) - 1, 4)) for h in lines]
        self.check(cases, got)

    @unittest.skipUnless(sys.platform == "win32", "needs cmd.exe")
    def test_batch(self):
        cases, script = [], []
        for seed in range(60):
            payload = ob.PAYLOADS["powershell"][seed % len(ob.PAYLOADS["powershell"])]
            rng = random.Random(seed)
            blob = base64.b64encode(payload.encode("utf-16-le")).decode()
            cases.append(("batch_launcher", f"powershell -nop -w hidden -enc {blob}", ""))
            script.append(ob.batch_launcher(rng, payload, verb="echo"))
        self.check(cases, _run(["cmd", "/q", "/c"], "\r\n".join(script) + "\r\n", ".bat", "ascii"))


if __name__ == "__main__":
    unittest.main()
