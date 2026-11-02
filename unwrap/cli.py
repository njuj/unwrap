"""Command-line entry point. Exit codes: 0 ok · 2 input error."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__
from .engine import MAX_LAYERS, Result, unwrap
from .indicators import behaviours, defang, extract
from .transforms import as_text

UNICODE = {"sep": "·", "fix": "└", "arrow": "→", "times": "×"}
ASCII = {"sep": "|", "fix": "`-", "arrow": "->", "times": "x"}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="unwrap",
        description="Peel obfuscation off PowerShell, JavaScript, VBScript and batch statically: Base64, gzip, XOR, "
                    "concatenation, format strings, char codes, reversing, packers. Nothing is ever executed.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("file", nargs="?", help="script to unwrap ('-' for stdin)")
    src.add_argument("-c", "--command", metavar="TEXT", help="unwrap this text instead (e.g. a command line from a log)")
    ap.add_argument("--full", action="store_true", help="print every layer in full, not just a preview")
    ap.add_argument("--layers-dir", type=Path, metavar="DIR", help="write each layer to DIR/layer-NN.txt")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-defang", action="store_true", help="print indicators live instead of defanged")
    ap.add_argument("--max-layers", type=int, default=MAX_LAYERS, metavar="N", help=f"default: {MAX_LAYERS}")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def read_input(args) -> tuple[str, str]:
    if args.command is not None:
        return args.command, "command line"
    if args.file == "-":
        raw = sys.stdin.buffer.read()
        name = "stdin"
    else:
        raw = Path(args.file).read_bytes()
        name = Path(args.file).name
    return as_text(raw) or raw.decode("utf-8", "replace"), name


def _glyphs(stream) -> dict:
    try:
        "".join(UNICODE.values()).encode(getattr(stream, "encoding", None) or "ascii")
        return UNICODE
    except (UnicodeEncodeError, LookupError):
        return ASCII


def _preview(text: str, limit: int) -> list[str]:
    flat = " ".join(text.split())
    return [flat if len(flat) <= limit else flat[:limit - 3] + "..."]


def render(result: Result, name: str, elapsed: float, full: bool, live: bool, color: bool, g: dict) -> str:
    def paint(text, code):
        return f"\033[{code}m{text}\033[0m" if color else text

    sep = f"  {g['sep']}  "
    lines = [paint(f" unwrap v{__version__}", "1;36") + paint(
        f"{sep}{name}{sep}{len(result.layers)} layer(s){sep}{result.rewrite_count} rewrite(s){sep}{elapsed:.2f}s",
        "2"), ""]
    for layer in result.layers:
        is_final = layer is result.layers[-1]
        title = "FINAL" if is_final and len(result.layers) > 1 else f"LAYER {layer.index}"
        meta = f"{layer.language}{sep}{len(layer.text):,} chars"
        if layer.rewrites:
            meta += f"{sep}rewrites: " + ", ".join(f"{k} {g['times']}{v}" for k, v in layer.rewrites.items())
        lines.append(paint(f" {title}", "1;35" if is_final else "1") + "  " + paint(meta, "2"))
        body = layer.text.splitlines() if (full or is_final) else _preview(layer.text, 160)
        for row in body[:400]:
            lines.append("   " + row)
        if layer.decoded_by:
            d = layer.decoded_by
            lines.append("   " + paint(f"{g['fix']} decoded: {d.technique}{sep}{d.detail}", "32"))
        lines.append("")
    if result.artifacts:
        lines.append(paint(" BINARY PAYLOADS", "1"))
        for a in result.artifacts:
            lines.append(f"   {a.kind:<16} {a.size:>10,} bytes  sha256 {a.sha256}  (layer {a.layer}, {a.technique})")
        lines.append("")
    texts = [layer.text for layer in result.layers]
    iocs = extract(texts)
    if iocs:
        lines.append(paint(" INDICATORS", "1"))
        for kind, values in iocs.items():
            for v in values[:25]:
                lines.append(f"   {kind:<9} " + (v if live else defang(v, kind)))
        lines.append("")
    found = behaviours(texts)
    if found:
        lines.append(paint(" BEHAVIOUR", "1"))
        width = max(len(t) for t, _, _ in found)
        for technique, description, evidence in found:
            lines.append(f"   {paint(technique.ljust(width), '35')}  {description}  " +
                         paint(f"{g['arrow']} {evidence[:90]}", "2"))
        lines.append("")
    lines.append(paint(f" stopped: {result.stopped}", "2"))
    return "\n".join(lines)


def to_json(result: Result, name: str, live: bool) -> dict:
    texts = [layer.text for layer in result.layers]
    iocs = extract(texts)
    return {
        "version": __version__, "input": name, "stopped": result.stopped, "final": result.final,
        "layers": [{"index": layer.index, "language": layer.language, "text": layer.text, "rewrites": layer.rewrites,
                    "decoded_by": None if not layer.decoded_by else {"technique": layer.decoded_by.technique,
                                                                      "detail": layer.decoded_by.detail}}
                   for layer in result.layers],
        "artifacts": [vars(a) for a in result.artifacts],
        "indicators": {k: [v if live else defang(v, k) for v in vals] for k, vals in iocs.items()},
        "behaviours": [{"technique": t, "description": d, "evidence": e} for t, d, e in behaviours(texts)],
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        text, name = read_input(args)
        started = time.perf_counter()
        result = unwrap(text, max_layers=max(1, args.max_layers))
        elapsed = time.perf_counter() - started
    except (OSError, ValueError) as e:
        print(f"unwrap: {e}", file=sys.stderr)
        return 2
    if args.layers_dir:
        args.layers_dir.mkdir(parents=True, exist_ok=True)
        for layer in result.layers:
            (args.layers_dir / f"layer-{layer.index:02d}.txt").write_text(layer.text, encoding="utf-8")
    if args.json:
        print(json.dumps(to_json(result, name, args.no_defang), indent=2, ensure_ascii=False))
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="replace")
        color = not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()
        print(render(result, name, elapsed, args.full, args.no_defang, color, _glyphs(sys.stdout)))
    return 0
