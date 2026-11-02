"""One test per rewrite: the folded result, and the cases that must be left alone."""

import unittest

from unwrap import transforms as T


def fold(fn, text):
    """Apply one rewrite to its fixed point, as the engine does."""
    for _ in range(50):
        new, n = fn(text)
        if not n or new == text:
            return text
        text = new
    return text


class PowerShell(unittest.TestCase):
    def test_ticks(self):
        # checked against Windows PowerShell 5.1: Writ`e-Output runs Write-Output
        self.assertEqual(fold(T.ps_ticks, "I`E`X (Ne`w-Obj`ect x)"), "IEX (New-Object x)")

    def test_ticks_that_mean_something_stay(self):
        # ...while a`nb is a line break, even unquoted
        self.assertEqual(fold(T.ps_ticks, 'Write-Host "a`tb`nc" a`nb `u{41}'), 'Write-Host "a`tb`nc" a`nb `u{41}')

    def test_ticks_inside_single_quotes_are_literal(self):
        self.assertEqual(fold(T.ps_ticks, "Write-Host 'I`E`X'"), "Write-Host 'I`E`X'")

    def test_char(self):
        self.assertEqual(fold(T.ps_char, "[char]73+[CHAR]0x45"), "'I'+'E'")

    def test_char_arrays(self):
        for code in ("[char[]](72,0x69) -join ''", "-join [char[]](72,105)", "(72,105|%{[char]$_})-join''",
                     "(72,105 | ForEach-Object { [char]$_ }) -join ''", "[string]::join('',[char[]](72,105))"):
            with self.subTest(code=code):
                self.assertEqual(fold(T.ps_char_arrays, code), "'Hi'")

    def test_char_array_separator(self):
        self.assertEqual(fold(T.ps_char_arrays, "[char[]](97,98) -join '-'"), "'a-b'")

    def test_format(self):
        self.assertEqual(fold(T.ps_format, "(\"{2}{0}{1}\" -f 'b','c','a')"), "'abc'")
        self.assertEqual(fold(T.ps_format, "('{0}{{x}}' -f 'a')"), "'a{x}'")

    def test_format_left_alone(self):
        for code in ("('{0,5}' -f 'a')", "('{0:N2}' -f 'a')", "('{0}{3}' -f 'a','b')"):
            with self.subTest(code=code):
                self.assertEqual(fold(T.ps_format, code), code)

    def test_concat(self):
        self.assertEqual(fold(T.ps_concat, "'Inv' + \"oke\"+'-Ex'"), "'Invoke-Ex'")

    def test_concat_keeps_quotes_right(self):
        self.assertEqual(fold(T.ps_concat, "'it''s' + ' ok'"), "'it''s ok'")

    def test_join(self):
        self.assertEqual(fold(T.ps_join, "('a','b','c') -join ''"), "'abc'")
        self.assertEqual(fold(T.ps_join, "('a','b') -JOIN '.'"), "'a.b'")
        self.assertEqual(fold(T.ps_join, "-join ('a','b')"), "'ab'")

    def test_reverse(self):
        self.assertEqual(fold(T.ps_reverse, "'olleh'[-1..-5] -join ''"), "'hello'")
        self.assertEqual(fold(T.ps_reverse, "'olleh'[-1..-3] -join ''"), "'hel'")
        self.assertEqual(fold(T.ps_reverse, "-join ('olleh'[-1..-($x.Length)])"), "'hello'")
        self.assertEqual(fold(T.ps_reverse, "'olleh'[-1..-('olleh'.Length)] -join ''"), "'hello'")

    def test_reverse_with_another_strings_length_stays(self):
        code = "'olleh'[-1..-('xy'.Length)] -join ''"
        self.assertEqual(fold(T.ps_reverse, code), code)

    def test_replace(self):
        self.assertEqual(fold(T.ps_replace, "'aXXbXXc' -replace 'XX',''"), "'abc'")
        self.assertEqual(fold(T.ps_replace, "'aXbxc' -replace 'x','-'"), "'a-b-c'")          # -replace ignores case
        self.assertEqual(fold(T.ps_replace, "'aXbxc' -creplace 'x','-'"), "'aXb-c'")
        self.assertEqual(fold(T.ps_replace, "'a.b.c'.Replace('.','')"), "'abc'")              # .Replace: no regex
        self.assertEqual(fold(T.ps_replace, "'ab' -replace '(a)(b)','$2$1'"), "'ba'")

    def test_vars(self):
        self.assertEqual(fold(T.ps_vars, "$a='Write-Output 1';iex $a"), "iex 'Write-Output 1'")

    def test_vars_reassigned_are_not_constants(self):
        code = "$a='x'; $a+='y'; iex $a"
        self.assertEqual(fold(T.ps_vars, code), code)

    def test_vars_in_expandable_strings_are_not_replaced(self):
        # "$a" expands at run time; pasting a quoted literal in there would change the string
        self.assertEqual(fold(T.ps_vars, "$a='x'\nWrite-Output \"v=$a\"; Write-Output $a"),
                         "$a='x'\nWrite-Output \"v=$a\"; Write-Output 'x'")

    def test_vars_still_referenced_keep_their_assignment(self):
        self.assertEqual(fold(T.ps_vars, "$a='x'; iex $a; Write-Output ${a}"), "$a='x'; iex 'x'; Write-Output ${a}")

    def test_vars_do_not_explode(self):
        code = "$a='" + "x" * 5000 + "';" + "$a;" * 1000           # 5 MB if propagated
        self.assertEqual(fold(T.ps_vars, code), code)

    def test_here_strings(self):
        code = "$s = @'\r\nWrite-Output 'it''s'\r\n'@\r\niex $s"
        self.assertEqual(fold(T.ps_vars, code), "iex @'\r\nWrite-Output 'it''s'\r\n'@")
        self.assertEqual(T.dec_iex_literal(fold(T.ps_vars, code)).text, "Write-Output 'it''s'")

    def test_invoke_alias(self):
        self.assertEqual(fold(T.ps_invoke_alias, "&'IEX' $x"), "IEX $x")
        self.assertEqual(fold(T.ps_invoke_alias, ".'iex'('a')"), "iex('a')")
        self.assertEqual(fold(T.ps_invoke_alias, "&'New-Object'Net.WebClient"), "New-Object Net.WebClient")

    def test_invoke_alias_leaves_paths_and_members(self):
        for code in ("& 'C:\\Tools\\x.exe' -q", "$obj.'Name'", "(Get-Item .).'Name'"):
            with self.subTest(code=code):
                self.assertEqual(fold(T.ps_invoke_alias, code), code)

    def test_automatic_variables_spell_iex(self):
        cases = {"$ShellId[1]": "'i'", "$PSHome[21]": "'i'", "$PSHome[34]": "'e'", "$env:Public[13]": "'i'",
                 "$env:ComSpec[4,15,25]": "('I','e','x')", "(gv '*mdr*').Name[3,11,2]": "('i','e','x')",
                 "$VerbosePreference.ToString()[1,3]": "('i','e')", "([String]$VerbosePreference)[1,3]": "('i','e')"}
        for code, expected in cases.items():
            with self.subTest(code=code):
                self.assertEqual(fold(T.ps_index, fold(T.ps_automatic, code)), expected)

    def test_automatic_variables_only_when_indexed(self):
        self.assertEqual(fold(T.ps_automatic, "Write-Output $PSHome"), "Write-Output $PSHome")

    def test_index_out_of_range_stays(self):
        self.assertEqual(fold(T.ps_index, "'abc'[7]"), "'abc'[7]")
        self.assertEqual(fold(T.ps_index, "'abc'[-1]"), "'c'")

    def test_list_plus_literal(self):
        self.assertEqual(fold(T.ps_index, "('i','e')+'x'"), "('i','e','x')")

    def test_parens(self):
        self.assertEqual(fold(T.ps_parens, "iex ( 'a' )"), "iex 'a'")
        self.assertEqual(fold(T.ps_parens, "$x.Invoke('a')"), "$x.Invoke('a')")      # a call, not grouping


class LiteralAwareness(unittest.TestCase):
    """Nested layers live inside literals of the outer one; folding inside them would break the quoting."""

    def test_rewrites_skip_code_inside_literals(self):
        for fn, code in ((T.ps_char, "Write-Output '[char]73'"),
                         (T.ps_concat, "Write-Output \"'a'+'b'\""),
                         (T.ps_char_arrays, "iex '[char[]](72,105) -join '''''"),
                         (T.js_fromcharcode, "x = 'String.fromCharCode(72)'"),
                         (T.vbs_chr, 'x = "Chr(72)"')):
            with self.subTest(code=code):
                self.assertEqual(fold(fn, code), code)


class JavaScript(unittest.TestCase):
    def test_fromcharcode(self):
        self.assertEqual(fold(T.js_fromcharcode, "String.fromCharCode(72, 0x69)"), "'Hi'")

    def test_atob(self):
        self.assertEqual(fold(T.js_atob, "atob('SGVsbG8=')"), "'Hello'")

    def test_unescape(self):
        self.assertEqual(fold(T.js_unescape, "unescape('%48%u0069')"), "'Hi'")
        self.assertEqual(fold(T.js_unescape, "decodeURIComponent('%C3%A9t%C3%A9')"), "'été'")

    def test_escapes(self):
        self.assertEqual(fold(T.js_escapes, "'\\x48\\u0069\\u{21}'"), "'Hi!'")

    def test_concat(self):
        self.assertEqual(fold(T.js_concat, "'a' + \"b\" +'c'"), "'abc'")

    def test_string_methods(self):
        self.assertEqual(fold(T.js_strings, "'cba'.split('').reverse().join('')"), "'abc'")
        self.assertEqual(fold(T.js_strings, "'aXbXc'.replace('X','')"), "'abXc'")          # first only
        self.assertEqual(fold(T.js_strings, "'aXbXc'.replaceAll('X','')"), "'abc'")
        self.assertEqual(fold(T.js_strings, "'aXbxc'.replace(/x/gi,'')"), "'abc'")

    def test_parens(self):
        self.assertEqual(fold(T.js_parens, "eval(('a'))"), "eval('a')")


class VBScript(unittest.TestCase):
    def test_chr(self):
        self.assertEqual(fold(T.vbs_chr, "Chr(72) & ChrW(&H69)"), '"H" & "i"')

    def test_constants(self):
        self.assertEqual(fold(T.vbs_chr, '"a" & vbCrLf & "b"'), '"a" & "\r\n" & "b"')

    def test_strings(self):
        self.assertEqual(fold(T.vbs_strings, '"a" & "b" + "c"'), '"abc"')
        self.assertEqual(fold(T.vbs_strings, 'StrReverse("cba")'), '"abc"')
        self.assertEqual(fold(T.vbs_strings, 'Replace("aXbXc", "X", "")'), '"abc"')
        self.assertEqual(fold(T.vbs_strings, 'x = ("say ""hi""")'), 'x = "say ""hi"""')


class Batch(unittest.TestCase):
    def test_carets(self):
        self.assertEqual(fold(T.bat_carets, "p^ow^er^shell -e^nc"), "powershell -enc")

    def test_set_expansion(self):
        code = "set a=pow\nset b=ershell\n%a%%b% -nop"
        self.assertEqual(fold(T.bat_vars, code), "set a=pow\nset b=ershell\npowershell -nop")

    def test_substrings(self):
        code = "set x=abcdefgh\necho %x:~2,3% %x:~-2% %x:~1%"
        self.assertEqual(fold(T.bat_vars, code).splitlines()[1], "echo cde gh bcdefgh")

    def test_variables_set_twice_stay(self):
        code = "set a=1\nset a=2\necho %a%"
        self.assertEqual(fold(T.bat_vars, code), code)


if __name__ == "__main__":
    unittest.main()
