"""Decoders, language detection and the engine's limits."""

import base64
import hashlib
import os
import random
import time
import unittest
import zlib
from unittest import mock

from unwrap import engine, transforms as T
from unwrap.engine import detect_language, unwrap


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class Decoders(unittest.TestCase):
    def test_encoded_command_spellings(self):
        blob = b64("Write-Output 1".encode("utf-16-le"))
        for flag in ("-e", "-ec", "-enc", "-EncodedCommand", "/enc", "-encodedc"):
            with self.subTest(flag=flag):
                d = T.dec_encoded_command(f"powershell.exe -NoP {flag} {blob}")
                self.assertEqual(d.text, "Write-Output 1")

    def test_encoded_command_needs_powershell(self):
        blob = b64("Write-Output 1".encode("utf-16-le"))
        self.assertIsNone(T.dec_encoded_command(f"someprogram -e {blob}"))

    def test_getstring_codecs(self):
        for codec, enc in (("UTF8", "utf-8"), ("Unicode", "utf-16-le"), ("ASCII", "ascii")):
            with self.subTest(codec=codec):
                code = f"[System.Text.Encoding]::{codec}.GetString([System.Convert]::FromBase64String(" \
                       f"'{b64('Write-Output 1'.encode(enc))}'))"
                self.assertEqual(T.dec_getstring(code).text, "Write-Output 1")

    def test_compressed(self):
        raw = zlib.compressobj(9, zlib.DEFLATED, -15)
        deflated = raw.compress(b"Write-Output 1") + raw.flush()
        code = f"New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('{b64(deflated)}'))"
        self.assertEqual(T.dec_compressed(code).text, "Write-Output 1")

    def test_decompression_bomb_is_refused(self):
        bomb = zlib.compress(b"\0" * (3 * 1024 * 1024))
        with mock.patch.object(T, "MAX_INFLATED", 1024 * 1024):
            self.assertIsNone(T.inflate(bomb[2:-4], gzip=False))
        self.assertIsNotNone(T.inflate(bomb[2:-4], gzip=False))

    def test_xor(self):
        blob = b64(bytes(b ^ 0x5A for b in b"Write-Output 1"))
        self.assertEqual(T.dec_xor(f"[Convert]::FromBase64String('{blob}') | % {{ $_ -bxor 0x5a }}").text,
                         "Write-Output 1")

    def test_iex_forms(self):
        for code in ("iex 'Write-Output 1'", "Invoke-Expression -Command 'Write-Output 1'",
                     "('Write-Output 1') | iex", "[ScriptBlock]::Create('Write-Output 1').Invoke()",
                     "& ([scriptblock]::Create('Write-Output 1'))", "icm ([ScriptBlock]::Create('Write-Output 1'))",
                     "$ExecutionContext.InvokeCommand.InvokeScript('Write-Output 1')",
                     "powershell -NoP -c 'Write-Output 1'", "$a = 1; iex 'Write-Output 1'; $b = 2"):
            with self.subTest(code=code):
                self.assertEqual(T.dec_iex_literal(code).text, "Write-Output 1")

    def test_js_wrappers(self):
        for code in ("eval('x()')", "new Function('x()')()", "Function(\"x()\")()", "document.write('x()')"):
            with self.subTest(code=code):
                self.assertEqual(T.dec_js_eval(code).text, "x()")

    def test_vbs_execute(self):
        for code in ('Execute "x"', 'ExecuteGlobal("x")', 'Eval("x")'):
            with self.subTest(code=code):
                self.assertEqual(T.dec_vbs_execute(code).text, "x")

    def test_blob(self):
        self.assertEqual(T.dec_blob(f"$x = '{b64(b'Write-Output from a plain base64 literal')}'").text,
                         "Write-Output from a plain base64 literal")
        hexed = "Write-Output from a hex string literal".encode().hex()
        self.assertEqual(T.dec_blob(f"x = '{hexed}'").text, "Write-Output from a hex string literal")

    def test_short_or_random_literals_are_not_blobs(self):
        self.assertIsNone(T.dec_blob("$x = 'SGVsbG8='"))
        self.assertIsNone(T.dec_blob("$id = '0123456789abcdef0123456789abcdef'"))


class Languages(unittest.TestCase):
    def test_detect(self):
        cases = {"powershell": "$a = Get-Item .; Write-Output $a", "javascript": "var a = function(x) { return x; };",
                 "vbscript": 'Dim a\r\nSet o = CreateObject("x")\r\nWScript.Echo a',
                 "batch": "@echo off\r\nset a=1\r\ngoto end", "unknown": "hello world"}
        for lang, code in cases.items():
            with self.subTest(lang=lang):
                self.assertEqual(detect_language(code), lang)


class LayerLanguage(unittest.TestCase):
    def test_the_wrapper_decides_the_next_layers_language(self):
        # keywords alone would call this PowerShell; Execute() says it is VBScript
        result = unwrap('Execute("Set sh = CreateObject(""WScript.Shell"") : sh.Run ""powershell -nop -c Get-Date"", 0")')
        self.assertEqual(result.layers[-1].language, "vbscript")
        result = unwrap("eval('WScript.Echo(\"powershell -c Get-Date\")')")
        self.assertEqual(result.layers[-1].language, "javascript")


class Engine(unittest.TestCase):
    def test_plain_input_is_one_layer(self):
        result = unwrap("Write-Output 1")
        self.assertEqual(len(result.layers), 1)
        self.assertEqual(result.stopped, "nothing left to decode")

    def test_binary_payload_becomes_an_artifact(self):
        pe = b"MZ\x90\x00" + bytes(range(256)) * 4
        code = f"$b = [Convert]::FromBase64String('{b64(pe)}')"
        result = unwrap(code)
        self.assertEqual(result.stopped, "binary payload extracted")
        self.assertEqual(result.artifacts[0].kind, "PE executable")
        self.assertEqual(result.artifacts[0].sha256, hashlib.sha256(pe).hexdigest())

    def test_layer_limit(self):
        code = "Write-Output 1"
        for _ in range(6):
            code = "iex '" + code.replace("'", "''") + "'"
        result = unwrap(code, max_layers=3)
        self.assertEqual(len(result.layers), 3)
        self.assertEqual(result.stopped, "layer limit (3) reached")
        self.assertEqual(unwrap(code).final, "Write-Output 1")

    def test_loop_guard(self):
        same = T.Decoded("test", "decodes to itself", "iex 'x'")
        with mock.patch.object(engine, "DECODERS", [lambda t: same]):
            result = unwrap("iex 'x'")
        self.assertEqual(result.stopped, "decoding loops back to an earlier layer")

    def test_input_size_limit(self):
        with self.assertRaises(ValueError):
            unwrap("x" * (engine.MAX_INPUT + 1))

    def test_rewrites_are_counted_per_layer(self):
        result = unwrap("iex ('Write-'+'Output 1')")
        self.assertEqual(result.layers[0].rewrites, {"concatenation": 1, "parentheses": 1})
        self.assertEqual(result.rewrite_count, 2)


class Robustness(unittest.TestCase):
    """Hostile input: malformed, huge, or built to make a naive deobfuscator hang or blow up."""

    def test_malformed_js_escapes(self):
        from unwrap.literals import js_value
        self.assertEqual(js_value(r"'\u{}\x\9\u{110000}\q'"), "u{}x9\\u{110000}q")

    def test_unterminated_quotes_are_linear(self):
        for code in ("'" + "a" * 500_000, '"' + "a" * 500_000, "iex ('" + "a''" * 100_000):
            started = time.perf_counter()
            unwrap(code)
            self.assertLess(time.perf_counter() - started, 20, code[:20])

    def test_large_random_blob(self):
        started = time.perf_counter()
        result = unwrap("$x = '" + b64(os.urandom(750_000)) + "'")
        self.assertLess(time.perf_counter() - started, 20)
        self.assertEqual(result.stopped, "nothing left to decode")

    def test_mutations_never_raise(self):
        import obfuscator as ob
        rng = random.Random(99)
        for _ in range(300):
            lang = rng.choice(list(ob.TECHNIQUES))
            code, _ = ob.stack(rng, rng.choice(ob.PAYLOADS[lang]), ob.TECHNIQUES[lang], rng.randint(1, 3))
            chars = list(code)
            for _ in range(rng.randint(1, 8)):
                chars.insert(rng.randrange(len(chars) + 1), rng.choice("'\"`$()[]{}+&|;,\\\n%^x0"))
            unwrap("".join(chars))                       # must not raise


if __name__ == "__main__":
    unittest.main()
