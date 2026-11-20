"""Containers: Windows shortcuts and HTML applications open into their command line or scripts, and what
the container itself gives away is reported. The payloads are harmless strings."""

import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from lnkwriter import make_lnk
from test_cli import run
from unwrap.cli import main  # noqa: F401  (run() calls it)
from unwrap.containers import open_container

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
ENC = base64.b64encode("Write-Output 'unwrap-test'".encode("utf-16-le")).decode()


def unwrap_bytes(raw: bytes, *extra):
    return run("-", "--json", *extra, stdin=raw)                     # through stdin: nothing written to disk


class Shortcuts(unittest.TestCase):
    def test_padded_powershell_shortcut_with_a_borrowed_icon(self):
        raw = make_lnk(PS, " " * 300 + f"-nop -w hidden -enc {ENC}",
                       icon=r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe", show=7,
                       workdir=r"%TEMP%", machine="desktop-kira01")
        c = open_container(raw, "Invoice.pdf.lnk")
        self.assertEqual((c.kind, c.language), ("lnk", "powershell"))
        self.assertEqual(c.fields["target"], PS)
        self.assertEqual(c.fields["built on"], "desktop-kira01")
        self.assertEqual(c.fields["window"], "minimized, not activated")
        techniques = [t for t, _, _ in c.findings]
        self.assertEqual(techniques, ["T1027", "T1204.002", "T1036", "T1564.003"])
        self.assertIn("300 leading blank characters", c.findings[0][2])

        code, out, _ = unwrap_bytes(raw)
        doc = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(doc["final"].strip(), "Write-Output 'unwrap-test'")
        self.assertEqual(doc["layers"][0]["decoded_by"]["technique"], "encoded-command")
        self.assertEqual(doc["container"]["kind"], "lnk")
        self.assertEqual([b["technique"] for b in doc["behaviours"]][:4], techniques)

    def test_target_from_the_shell_item_list(self):
        raw = make_lnk(r"C:\Windows\System32\cmd.exe", "/c echo unwrap-test", idlist_only=True)
        c = open_container(raw)
        self.assertEqual(c.fields["target"], r"C:\Windows\System32\cmd.exe")
        self.assertEqual((c.language, c.text), ("batch", r"C:\Windows\System32\cmd.exe /c echo unwrap-test"))

    def test_text_render_shows_the_container(self):
        code, out, _ = run("-", "--no-color", stdin=make_lnk(PS, f"-enc {ENC}"))
        self.assertEqual(code, 0)
        self.assertIn(" CONTAINER  lnk", out)
        self.assertIn("starts powershell.exe", out)
        self.assertNotIn("borrows", out)                              # no icon given

    def test_damaged_shortcut_is_an_input_error(self):
        code, _, err = unwrap_bytes(make_lnk(PS, "x")[:0x4C] + b"\xff\xff\x01")
        self.assertEqual(code, 2)
        self.assertIn("damaged shortcut", err)

    @unittest.skipUnless(sys.platform == "win32", "WScript.Shell writes the shortcut")
    def test_a_shortcut_windows_itself_wrote(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "real.lnk")
            ps = (f"$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{path}'); $s.TargetPath = '{PS}'; "
                  "$s.Arguments = '-nop -c Write-Output unwrap-test'; $s.WorkingDirectory = 'C:\\Windows'; "
                  "$s.IconLocation = 'C:\\Windows\\System32\\imageres.dll,2'; $s.WindowStyle = 7; $s.Save()")
            subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=True, capture_output=True, timeout=120)
            c = open_container(Path(path).read_bytes())
        self.assertEqual(c.fields["target"].lower(), PS.lower())
        self.assertEqual(c.text.split(" ", 1)[1], "-nop -c Write-Output unwrap-test")
        self.assertEqual(c.fields["working dir"], "C:\\Windows")
        self.assertIn("built on", c.fields)
        self.assertEqual([t for t, _, _ in c.findings], ["T1204.002", "T1036", "T1564.003"])


class HtmlApplications(unittest.TestCase):
    def test_hta_vbscript(self):
        hidden = 'MsgBox "unwrap-test"'[::-1].replace('"', '""')
        hta = (f'<html><head><hta:application id="x" windowstate="minimize"/></head><body>\n'
               f'<script language="VBScript">\nExecute StrReverse("{hidden}")\nself.close\n</script></body></html>')
        code, out, _ = unwrap_bytes(hta.encode())
        doc = json.loads(out)
        self.assertEqual(doc["container"]["kind"], "hta")
        self.assertEqual(doc["layers"][0]["language"], "vbscript")
        self.assertIn('MsgBox "unwrap-test"', doc["final"])
        self.assertIn("T1218.005", [b["technique"] for b in doc["behaviours"]])

    def test_html_smuggling_hands_back_the_file(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("readme.txt", "unwrap-test")
        blob = base64.b64encode(buf.getvalue()).decode()
        page = ("<!DOCTYPE html><html><body><script>\n"
                f"var d = atob('{blob}');\nvar a = new Uint8Array(d.length);\n"
                "for (var i = 0; i < d.length; i++) a[i] = d.charCodeAt(i);\n"
                "var b = new Blob([a], {type: 'application/zip'});\nvar l = document.createElement('a');\n"
                "l.href = URL.createObjectURL(b); l.download = 'invoice.zip'; l.click();\n</script></body></html>")
        code, out, _ = unwrap_bytes(page.encode())
        doc = json.loads(out)
        self.assertEqual(doc["container"]["kind"], "html")
        self.assertIn("T1027.006", [b["technique"] for b in doc["behaviours"]])
        self.assertEqual(doc["artifacts"][0]["kind"], "ZIP archive")

    def test_plain_scripts_are_not_containers(self):
        self.assertIsNone(open_container(b"Write-Output 'hi'", "a.ps1"))
        self.assertIsNone(open_container(b"<html><body>no scripts here</body></html>", "a.html"))


if __name__ == "__main__":
    unittest.main()
