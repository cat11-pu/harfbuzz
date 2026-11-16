#!/usr/bin/env python3
"""Randomized shaping property test.

Each case creates a new SFNT font by dropping or damaging tables from a base
font, then shapes random text containing combining marks, RTL runs, and
zero-width joiners.  The text is shaped twice in fresh processes and the glyph
sequences are compared.  Run hb-shape under ASan/UBSan with leak detection so
memory errors and leaks are reported as failures.

The script uses only the Python standard library.  It is intentionally not
wired into the default Meson test suite because it needs an instrumented
hb-shape and a small font corpus.

This directory is removed from ``sys.path`` before importing stdlib modules,
because ``test/fuzzing/glob.py`` shadows the standard library ``glob`` module.
"""

from __future__ import annotations

import os
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [
    entry for entry in sys.path
    if os.path.abspath(entry or os.getcwd()) != _SCRIPT_DIR
]

import argparse
import hashlib
import json
import random
import re
import shutil
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional


ROOT = Path(__file__).resolve().parents[2]

DEFAULT_BASE_FONTS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
    "test/api/fonts/Qahiri-Regular.ttf",
    "test/api/fonts/Mada-VF.ttf",
    "test/api/fonts/Estedad-VF.ttf",
    "test/api/fonts/Roboto-Regular.abc.ttf",
    "test/shape/data/in-house/fonts/TradArabicTest.ttf",
    "test/subset/data/fonts/Khmer.ttf",
    "test/subset/data/fonts/IndicTestJalandhar-Regular.ttf",
    "test/subset/data/fonts/Molengo-Regular.ttf",
    "test/subset/data/fonts/AdobeVFPrototype.otf",
    "test/subset/data/fonts/RobotoDelta-Roman-VF-subset.ttf",
    "test/subset/data/fonts/BungeeColor-Regular.ttf",
    "test/subset/data/fonts/NotoColrEmojiGlyf-Regular.subset.ttf",
    "test/api/fonts/NotoColorEmoji.subset.default.2049.ttf",
    "test/api/fonts/sbix_X.ttf",
    "test/fuzzing/fonts/noto_handwriting-cff_colr_1.otf",
    "test/subset/data/fonts/Handjet.ttf",
    "test/subset/data/fonts/Foldit.ttf",
]

LATIN = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
HEBREW = "אבגדהוזחטיכלמנסעפצקרשת"
ARABIC = "ابتثجحخدذرزسشصضطظعغفقكلمنهوي"
DEVANAGARI = "कखगघचछजझटठडढतथदधनपफबभमयरलवशषसह"

COMBINING = [
    "\u0300", "\u0301", "\u0302", "\u0303", "\u0304", "\u0306", "\u0307",
    "\u0308", "\u030a", "\u030c", "\u0323", "\u0327", "\u0328", "\u0331",
    "\u0345", "\u20d0", "\u20d1", "\u20d6", "\u20d7",
]
ARABIC_MARKS = [
    "\u064b", "\u064c", "\u064d", "\u064e", "\u064f", "\u0650", "\u0651",
    "\u0652", "\u0653", "\u0654", "\u0655", "\u0670",
]
HEBREW_MARKS = [
    "\u05b0", "\u05b1", "\u05b2", "\u05b3", "\u05b4", "\u05b5", "\u05b6",
    "\u05b7", "\u05b8", "\u05b9", "\u05bb", "\u05bc", "\u05c1", "\u05c2",
    "\u05c7",
]
DEVANAGARI_MARKS = [
    "\u093c", "\u093e", "\u093f", "\u0940", "\u0941", "\u0942", "\u0943",
    "\u0944", "\u0947", "\u0948", "\u094b", "\u094c", "\u094d", "\u0951",
    "\u0952", "\u0953", "\u0954",
]

ZWJ = "\u200d"
ZWNJ = "\u200c"
WORD_JOINER = "\u2060"
ZERO_WIDTHS = [ZWJ, ZWNJ, WORD_JOINER]
BIDI_CONTROLS = [
    "\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d",
    "\u202e", "\u2066", "\u2067", "\u2068", "\u2069",
]
EMOJI = ["\U0001f468", "\U0001f469", "\U0001f467", "\U0001f466", "\U0001f30d"]

FEATURES = [
    "kern", "liga", "clig", "calt", "rlig", "ccmp", "mark", "mkmk", "locl",
    "dlig", "ss01", "frac", "zero",
]

MISSING_TABLE_ROTATION = [
    b"BASE", b"CBDT", b"CBLC", b"CFF ", b"CFF2", b"COLR", b"CPAL", b"DSIG",
    b"FFTM", b"GDEF", b"GPOS", b"GSUB", b"HVAR", b"MATH", b"MVAR", b"OS/2",
    b"STAT", b"avar", b"cmap", b"cvt ", b"fpgm", b"fvar", b"gasp", b"glyf",
    b"gvar", b"hdmx", b"head", b"hhea", b"hmtx", b"kern", b"loca", b"maxp",
    b"meta", b"morx", b"name", b"post", b"prep", b"sbix", b"SVG ",
]

SFNT_VERSIONS = {b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1"}


@dataclass(frozen=True)
class Sfnt:
    version: bytes
    tables: tuple[tuple[bytes, bytes], ...]


@dataclass
class RunResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    elapsed: float
    timed_out: bool = False


@dataclass
class Failure:
    kind: str
    signature: str
    detail: str
    run1: RunResult
    run2: RunResult


@dataclass
class Case:
    index: int
    base_path: Path
    base_sha256: str
    font_path: Path
    text_path: Path
    text: str
    direction: str
    language: str
    features: tuple[str, ...]
    cluster_level: int
    preserve_default_ignorables: bool
    dropped_tables: tuple[str, ...]
    modified_tables: tuple[str, ...]
    coverage: dict[str, bool]


def tag_name(tag: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in tag)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checksum(data: bytes) -> int:
    padded = data + b"\0" * ((-len(data)) & 3)
    if not padded:
        return 0
    return sum(struct.unpack(f">{len(padded) // 4}I", padded)) & 0xFFFFFFFF


def read_sfnt(path: Path) -> Sfnt:
    blob = path.read_bytes()
    if len(blob) < 12 or blob[:4] == b"ttcf":
        raise ValueError("not a single-face SFNT")
    version = blob[:4]
    if version not in SFNT_VERSIONS:
        raise ValueError(f"unsupported SFNT version {version!r}")

    num_tables = struct.unpack_from(">H", blob, 4)[0]
    if not num_tables or num_tables > 4096 or 12 + 16 * num_tables > len(blob):
        raise ValueError("invalid SFNT directory")

    tables: list[tuple[bytes, bytes]] = []
    for i in range(num_tables):
        record = 12 + 16 * i
        tag = blob[record:record + 4]
        offset, length = struct.unpack_from(">II", blob, record + 8)
        if offset > len(blob) or length > len(blob) - offset:
            raise ValueError(f"table {tag_name(tag)} is out of bounds")
        tables.append((tag, blob[offset:offset + length]))

    return Sfnt(version, tuple(tables))


def write_sfnt(sfnt: Sfnt) -> bytes:
    tables = sorted(sfnt.tables, key=lambda item: item[0])
    num_tables = len(tables)
    if not num_tables or num_tables > 0xFFFF:
        raise ValueError("invalid table count")

    max_pow2 = 1 << (num_tables.bit_length() - 1)
    search_range = max_pow2 * 16
    entry_selector = max_pow2.bit_length() - 1
    range_shift = num_tables * 16 - search_range

    directory_size = 12 + 16 * num_tables
    records: list[tuple[bytes, int, int, int]] = []
    body = bytearray()

    for tag, data in tables:
        if tag == b"head" and len(data) >= 12:
            data = data[:8] + b"\0\0\0\0" + data[12:]
        offset = directory_size + len(body)
        records.append((tag, checksum(data), offset, len(data)))
        body.extend(data)
        body.extend(b"\0" * ((-len(body)) & 3))

    header = sfnt.version + struct.pack(
        ">HHHH", num_tables, search_range, entry_selector, range_shift
    )
    directory = bytearray()
    for tag, table_checksum, offset, length in records:
        directory.extend(tag)
        directory.extend(struct.pack(">III", table_checksum, offset, length))

    blob = bytearray(header)
    blob.extend(directory)
    blob.extend(body)

    for tag, _checksum, offset, _length in records:
        if tag == b"head" and offset + 12 <= len(blob):
            adjustment = (0xB1B0AFBA - checksum(bytes(blob))) & 0xFFFFFFFF
            struct.pack_into(">I", blob, offset + 8, adjustment)
            break

    return bytes(blob)


def escape_text(text: str) -> str:
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif 32 <= cp < 127:
            out.append(ch)
        elif cp <= 0xFFFF:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(f"\\U{cp:08x}")
    return "".join(out)


def random_cluster(rng: random.Random) -> str:
    kind = rng.choice(["latin", "hebrew", "arabic", "devanagari", "emoji"])
    if kind == "latin":
        base = rng.choice(LATIN)
        marks = COMBINING
    elif kind == "hebrew":
        base = rng.choice(HEBREW)
        marks = HEBREW_MARKS
    elif kind == "arabic":
        base = rng.choice(ARABIC)
        marks = ARABIC_MARKS
    elif kind == "devanagari":
        base = rng.choice(DEVANAGARI)
        marks = DEVANAGARI_MARKS
    else:
        return rng.choice(EMOJI) + (rng.choice(["\ufe0f", ""]))

    cluster = base
    for _ in range(rng.randint(1, 3)):
        cluster += rng.choice(marks)
    return cluster


def random_zwj_alternation(rng: random.Random, separator: str) -> str:
    alphabet = LATIN + HEBREW + ARABIC + DEVANAGARI
    chars = [rng.choice(alphabet) for _ in range(rng.randint(3, 7))]
    return separator.join(chars)


def make_text(rng: random.Random) -> tuple[str, dict[str, bool]]:
    segments: list[str] = []

    segments.append(rng.choice(LATIN) + "".join(
        rng.choice(COMBINING) for _ in range(rng.randint(1, 3))
    ))
    rtl_word = "".join(rng.choice(HEBREW if rng.random() < 0.45 else ARABIC)
                       for _ in range(rng.randint(3, 7)))
    if rng.random() < 0.5:
        rtl_word += rng.choice(HEBREW_MARKS + ARABIC_MARKS)
    segments.append(rtl_word)
    segments.append(random_zwj_alternation(rng, ZWJ))
    segments.append(random_zwj_alternation(rng, ZWNJ))
    segments.append(random_zwj_alternation(rng, rng.choice(ZERO_WIDTHS)))

    for _ in range(rng.randint(3, 8)):
        kind = rng.choice([
            "latin", "hebrew", "arabic", "devanagari", "emoji", "combining",
            "zwj", "zwnj", "bidi",
        ])
        if kind == "latin":
            segments.append("".join(rng.choice(LATIN)
                                    for _ in range(rng.randint(1, 8))))
        elif kind == "hebrew":
            segments.append("".join(rng.choice(HEBREW)
                                    for _ in range(rng.randint(1, 8))))
        elif kind == "arabic":
            segments.append("".join(rng.choice(ARABIC)
                                    for _ in range(rng.randint(1, 8))))
        elif kind == "devanagari":
            segments.append("".join(rng.choice(DEVANAGARI)
                                    for _ in range(rng.randint(1, 8))))
        elif kind == "emoji":
            segments.append(rng.choice(EMOJI))
            if rng.random() < 0.5:
                segments.append(ZWJ + rng.choice(EMOJI))
        elif kind == "combining":
            segments.append(random_cluster(rng))
        elif kind == "zwj":
            segments.append(random_zwj_alternation(rng, ZWJ))
        elif kind == "zwnj":
            segments.append(random_zwj_alternation(rng, ZWNJ))
        else:
            segments.append(rng.choice(BIDI_CONTROLS))

    rng.shuffle(segments)
    text = "".join(segments)

    if rng.random() < 0.25:
        text = rng.choice(COMBINING + ARABIC_MARKS + HEBREW_MARKS) + text
    if rng.random() < 0.25:
        text += rng.choice(COMBINING + ARABIC_MARKS + HEBREW_MARKS)

    coverage = {
        "combining": any(ord(ch) in range(0x0300, 0x2100) for ch in text),
        "rtl": any(
            "\u0590" <= ch <= "\u08ff" or "\ufb1d" <= ch <= "\ufdff"
            or "\ufe70" <= ch <= "\ufeff"
            for ch in text
        ),
        "zwj": ZWJ in text,
        "zwnj": ZWNJ in text,
    }
    return text, coverage


def make_mutant(
    rng: random.Random,
    sfnt: Sfnt,
    index: int,
) -> tuple[Sfnt, list[str], list[str]]:
    present_tags = {tag for tag, _data in sfnt.tables}
    target = MISSING_TABLE_ROTATION[index % len(MISSING_TABLE_ROTATION)]
    if target not in present_tags:
        target = rng.choice(sorted(present_tags))

    dropped = {target}
    unique_tags = sorted(present_tags)
    extra = rng.choices([0, 1, 2, 3], weights=[35, 35, 20, 10])[0]
    for _ in range(extra):
        available = [tag for tag in unique_tags if tag not in dropped]
        if len(available) <= 1:
            break
        dropped.add(rng.choice(available))

    kept = [(tag, data) for tag, data in sfnt.tables if tag not in dropped]
    if not kept:
        kept = [rng.choice(sfnt.tables)]

    modified: list[str] = []
    mutation_roll = rng.random()
    if mutation_roll < 0.35:
        candidates = [
            (i, tag) for i, (tag, data) in enumerate(kept)
            if data and tag in present_tags
        ]
        if candidates:
            pos, tag = rng.choice(candidates)
            _old_tag, data = kept[pos]
            if mutation_roll < 0.18:
                new_data = b""
                modified.append(f"{tag_name(tag)}:empty")
            elif mutation_roll < 0.27:
                new_data = data[:rng.randrange(len(data) + 1)]
                modified.append(f"{tag_name(tag)}:truncated-to-{len(new_data)}")
            else:
                changed = bytearray(data)
                for _ in range(rng.randint(1, 4)):
                    at = rng.randrange(len(changed))
                    changed[at] ^= 1 << rng.randrange(8)
                new_data = bytes(changed)
                modified.append(f"{tag_name(tag)}:bitflip")
            kept[pos] = (tag, new_data)

    return (
        Sfnt(sfnt.version, tuple(kept)),
        [tag_name(tag) for tag in sorted(dropped)],
        modified,
    )


def sanitizer_environment() -> dict[str, str]:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = (
        "detect_leaks=1:halt_on_error=1:abort_on_error=1:"
        "detect_stack_use_after_return=1:allocator_may_return_null=1:"
        "print_stacktrace=1:strict_string_checks=1"
    )
    env["LSAN_OPTIONS"] = "exitcode=23:report_objects=1:max_leaks=20"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    return env


def build_command(
    hb_shape: Path,
    font_path: Path,
    text_path: Path,
    direction: str,
    language: str,
    features: Iterable[str],
    cluster_level: int,
    preserve_default_ignorables: bool,
    verify: bool,
) -> list[str]:
    command = [
        str(hb_shape),
        f"--font-file={font_path}",
        f"--text-file={text_path}",
        "--no-glyph-names",
        "--no-positions",
        "--no-clusters",
        "--no-advances",
        "--output-format=text",
        f"--direction={direction}",
        f"--language={language}",
    ]
    feature_list = list(features)
    if feature_list:
        command.append("--features=" + ",".join(feature_list))
    if cluster_level:
        command.append(f"--cluster-level={cluster_level}")
    if preserve_default_ignorables:
        command.append("--preserve-default-ignorables")
    if verify:
        command.append("--verify")
    return command


def run_once(
    command: list[str],
    env: dict[str, str],
    timeout: float,
) -> RunResult:
    start = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout,
            check=False,
        )
        return RunResult(
            completed.returncode,
            completed.stdout,
            completed.stderr,
            time.monotonic() - start,
        )
    except subprocess.TimeoutExpired as error:
        return RunResult(
            -1,
            error.stdout or b"",
            error.stderr or b"",
            time.monotonic() - start,
            timed_out=True,
        )


def asan_report(stderr: bytes) -> Optional[tuple[str, str]]:
    text = stderr.decode("utf-8", "replace")
    match = re.search(r"ERROR: AddressSanitizer: ([^\n]+)", text)
    if match:
        detail = match.group(1).strip()
        kind_match = re.match(r"([A-Za-z0-9_-]+)", detail)
        kind = kind_match.group(1) if kind_match else detail
        return kind, detail
    return None


def classify(run1: RunResult, run2: RunResult) -> Optional[Failure]:
    stderr = run1.stderr + b"\n" + run2.stderr
    stderr_text = stderr.decode("utf-8", "replace")

    if run1.timed_out or run2.timed_out:
        return Failure("timeout", "timeout", "hb-shape exceeded the timeout", run1, run2)

    leak = "LeakSanitizer" in stderr_text
    sanitizer = asan_report(stderr)
    if sanitizer:
        sanitizer_kind, sanitizer_detail = sanitizer
        kind = "out_of_bounds" if (
            "buffer-overflow" in sanitizer_kind
            or "use-after-" in sanitizer_kind
            or "container-overflow" in sanitizer_kind
        ) else "asan"
        return Failure(
            kind,
            f"{kind}:{sanitizer_kind}",
            sanitizer_detail,
            run1,
            run2,
        )
    if leak:
        match = re.search(r"SUMMARY: [^\n]+", stderr_text)
        detail = match.group(0) if match else "LeakSanitizer detected a leak"
        return Failure("leak", "leak", detail, run1, run2)

    ubsan_match = re.search(r"runtime error: [^\n]+", stderr_text)
    if ubsan_match:
        detail = ubsan_match.group(0)
        return Failure("ubsan", "ubsan", detail, run1, run2)

    if run1.returncode < 0 or run2.returncode < 0:
        signals = f"{run1.returncode}/{run2.returncode}"
        return Failure(
            "crash",
            f"signal:{signals}",
            f"hb-shape terminated by signal ({signals})",
            run1,
            run2,
        )

    if "buffer verify error:" in stderr_text:
        match = re.search(r"buffer verify error: [^\n]+", stderr_text)
        detail = match.group(0) if match else "buffer verify error"
        return Failure("verify", "verify", detail, run1, run2)

    if run1.returncode != 0 or run2.returncode != 0:
        codes = f"{run1.returncode}/{run2.returncode}"
        return Failure(
            "exit",
            f"exit:{codes}",
            f"hb-shape exited with status {codes}",
            run1,
            run2,
        )

    if run1.stdout != run2.stdout:
        detail = (
            f"glyph output differs ({len(run1.stdout)} vs "
            f"{len(run2.stdout)} bytes)"
        )
        return Failure("nondeterministic", "nondeterministic", detail, run1, run2)

    return None


def run_pair(
    command: list[str],
    env: dict[str, str],
    timeout: float,
) -> tuple[RunResult, RunResult, Optional[Failure]]:
    run1 = run_once(command, env, timeout)
    run2 = run_once(command, env, timeout)
    return run1, run2, classify(run1, run2)


def ddmin(items: list, test: Callable[[list], bool]) -> list:
    n = 2
    while len(items) >= 2:
        parts = max(1, min(n, len(items)))
        size, remainder = divmod(len(items), parts)
        chunks: list[tuple[int, int]] = []
        start = 0
        for i in range(parts):
            end = start + size + (1 if i < remainder else 0)
            chunks.append((start, end))
            start = end

        reduced = False
        for start, end in chunks:
            candidate = items[:start] + items[end:]
            if test(candidate):
                items = candidate
                n = max(2, n - 1)
                reduced = True
                break
        if reduced:
            continue
        if n >= len(items):
            break
        n = min(len(items), n * 2)
    return items


def minimize_failure(
    case: Case,
    failure: Failure,
    sfnt: Sfnt,
    hb_shape: Path,
    env: dict[str, str],
    timeout: float,
    verify: bool,
    out_dir: Path,
) -> tuple[Sfnt, str, dict]:
    failure_dir = out_dir / "failures" / f"case-{case.index:03d}"
    failure_dir.mkdir(parents=True, exist_ok=True)

    (failure_dir / "font-original.ttf").write_bytes(
        case.font_path.read_bytes()
    )
    (failure_dir / "text-original.txt").write_text(case.text, encoding="utf-8")

    work_dir = failure_dir / "minimize-work"
    work_dir.mkdir(exist_ok=True)
    candidate_font = work_dir / "candidate.ttf"
    candidate_text = work_dir / "candidate.txt"

    def test_font(tables: list[tuple[bytes, bytes]], text: str) -> bool:
        if not tables:
            return False
        candidate_font.write_bytes(write_sfnt(Sfnt(sfnt.version, tuple(tables))))
        candidate_text.write_text(text, encoding="utf-8")
        command = build_command(
            hb_shape,
            candidate_font,
            candidate_text,
            case.direction,
            case.language,
            case.features,
            case.cluster_level,
            case.preserve_default_ignorables,
            verify,
        )
        _run1, _run2, candidate_failure = run_pair(command, env, timeout)
        return candidate_failure is not None and (
            candidate_failure.signature == failure.signature
        )

    def test_text(text: str, tables: list[tuple[bytes, bytes]]) -> bool:
        return test_font(tables, text)

    tables = list(sfnt.tables)
    text = case.text
    for _ in range(2):
        tables = ddmin(tables, lambda candidate: test_font(candidate, text))
        codepoints = list(text)
        codepoints = ddmin(
            codepoints,
            lambda candidate: test_text("".join(candidate), tables),
        )
        text = "".join(codepoints)

    minimized = Sfnt(sfnt.version, tuple(tables))
    minimized_bytes = write_sfnt(minimized)
    (failure_dir / "font-minimized.ttf").write_bytes(minimized_bytes)
    (failure_dir / "text-minimized.txt").write_text(text, encoding="utf-8")
    shutil.rmtree(work_dir, ignore_errors=True)

    command = build_command(
        hb_shape,
        failure_dir / "font-minimized.ttf",
        failure_dir / "text-minimized.txt",
        case.direction,
        case.language,
        case.features,
        case.cluster_level,
        case.preserve_default_ignorables,
        verify,
    )
    run1, run2, minimized_failure = run_pair(command, env, timeout)
    metadata = {
        "kind": failure.kind,
        "signature": failure.signature,
        "detail": failure.detail,
        "font_tables": [tag_name(tag) for tag, _data in minimized.tables],
        "font_size": len(minimized_bytes),
        "font_sha256": sha256_bytes(minimized_bytes),
        "text": escape_text(text),
        "text_utf8_hex": text.encode("utf-8").hex(),
        "command": [str(part) for part in command],
        "reproduced": minimized_failure is not None
        and minimized_failure.signature == failure.signature,
        "run1_returncode": run1.returncode,
        "run2_returncode": run2.returncode,
        "run1_stdout": run1.stdout.decode("utf-8", "replace"),
        "run2_stdout": run2.stdout.decode("utf-8", "replace"),
        "run1_stderr": run1.stderr.decode("utf-8", "replace")[:20000],
        "run2_stderr": run2.stderr.decode("utf-8", "replace")[:20000],
    }
    (failure_dir / "minimized.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return minimized, text, metadata


def find_hb_shape(explicit: Optional[str]) -> Path:
    if explicit:
        path = Path(explicit)
        if not path.exists():
            raise FileNotFoundError(path)
        return path
    for relative in ("build-asan/util/hb-shape", "build/util/hb-shape"):
        path = ROOT / relative
        if path.exists():
            return path
    found = shutil.which("hb-shape")
    if found:
        return Path(found)
    raise FileNotFoundError("hb-shape not found; pass --hb-shape")


def resolve_base_fonts(paths: Iterable[str]) -> list[tuple[Path, Sfnt]]:
    resolved: list[tuple[Path, Sfnt]] = []
    seen = set()
    for item in paths:
        path = Path(item)
        if not path.is_absolute():
            path = ROOT / path
        path = path.resolve()
        if path in seen or not path.exists():
            continue
        try:
            sfnt = read_sfnt(path)
        except ValueError as error:
            print(f"skipping base font {path}: {error}", file=sys.stderr)
            continue
        seen.add(path)
        resolved.append((path, sfnt))
    if not resolved:
        raise RuntimeError("no usable base fonts")
    return resolved


def hb_shape_version(hb_shape: Path, env: dict[str, str]) -> str:
    try:
        completed = subprocess.run(
            [str(hb_shape), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=10,
            check=False,
        )
        return completed.stdout.decode("utf-8", "replace").strip()
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hb-shape", help="path to sanitizer-instrumented hb-shape")
    parser.add_argument(
        "--base-font",
        action="append",
        default=None,
        help="base font path (repeatable); defaults to a small built-in corpus",
    )
    parser.add_argument("--cases", type=int, default=200)
    parser.add_argument("--seed", type=int, default=20261116)
    parser.add_argument(
        "--out-dir",
        default=str(ROOT / "artifacts" / "shape-property-200"),
    )
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="also pass --verify and report buffer verify errors",
    )
    parser.add_argument(
        "--keep-fonts",
        action="store_true",
        help="keep all generated fonts and texts, not just failures",
    )
    args = parser.parse_args()

    if args.cases < 1:
        parser.error("--cases must be positive")

    hb_shape = find_hb_shape(args.hb_shape)
    base_fonts = resolve_base_fonts(
        args.base_font if args.base_font else DEFAULT_BASE_FONTS
    )
    env = sanitizer_environment()
    rng = random.Random(args.seed)

    out_dir = Path(args.out_dir).resolve()
    fonts_dir = out_dir / "fonts"
    texts_dir = out_dir / "texts"
    fonts_dir.mkdir(parents=True, exist_ok=True)
    texts_dir.mkdir(parents=True, exist_ok=True)

    started = time.time()
    cases_path = out_dir / "cases.jsonl"
    cases_path.write_text("", encoding="utf-8")
    failures: list[dict] = []
    stats = {
        "out_of_bounds": 0,
        "leak": 0,
        "ubsan": 0,
        "asan": 0,
        "verify": 0,
        "timeout": 0,
        "crash": 0,
        "exit": 0,
        "nondeterministic": 0,
    }
    dropped_counts: dict[str, int] = {}
    modified_counts: dict[str, int] = {}
    base_counts: dict[str, int] = {}
    direction_counts: dict[str, int] = {}
    coverage_counts = {"combining": 0, "rtl": 0, "zwj": 0, "zwnj": 0}
    seen_font_hashes: set[str] = set()
    total_runs = 0

    for index in range(args.cases):
        target = MISSING_TABLE_ROTATION[index % len(MISSING_TABLE_ROTATION)]
        candidates = [
            item for item in base_fonts if target in {tag for tag, _ in item[1].tables}
        ]
        base_path, base_sfnt = (
            rng.choice(candidates) if candidates else rng.choice(base_fonts)
        )
        base_sha = sha256_bytes(base_path.read_bytes())
        mutant, dropped, modified = make_mutant(rng, base_sfnt, index)
        font_bytes = write_sfnt(mutant)
        font_hash = sha256_bytes(font_bytes)
        if font_hash in seen_font_hashes:
            used_tags = {tag for tag, _data in mutant.tables}
            padding_tag = f"Z{index:03d}".encode("ascii")
            while padding_tag in used_tags:
                padding_tag = b"Z" + bytes([(padding_tag[1] + 1) & 0xFF]) + padding_tag[2:]
            padding = bytes(rng.randrange(256) for _ in range(rng.randint(1, 32)))
            mutant = Sfnt(mutant.version, mutant.tables + ((padding_tag, padding),))
            modified.append(f"{tag_name(padding_tag)}:collision-padding")
            font_bytes = write_sfnt(mutant)
            font_hash = sha256_bytes(font_bytes)
        seen_font_hashes.add(font_hash)

        font_path = fonts_dir / f"case-{index:03d}.ttf"
        text_path = texts_dir / f"case-{index:03d}.txt"
        font_path.write_bytes(font_bytes)

        text, text_coverage = make_text(rng)
        text_path.write_text(text, encoding="utf-8")

        direction = rng.choices(["auto", "rtl", "ltr"], weights=[55, 30, 15])[0]
        rtl_word = any(
            "\u0590" <= ch <= "\u08ff" for ch in text
        )
        if rtl_word and direction == "auto":
            language = rng.choice(["ar", "he", "fa", "ur"])
        else:
            language = rng.choice(["en", "und", "ar", "he"])
        feature_list = tuple(
            f"{rng.choice(['+', '-'])}{name}"
            for name in rng.sample(FEATURES, rng.randint(0, 3))
        )
        cluster_level = rng.choices([0, 1, 2], weights=[70, 20, 10])[0]
        preserve_default_ignorables = rng.random() < 0.20

        command = build_command(
            hb_shape,
            font_path,
            text_path,
            direction,
            language,
            feature_list,
            cluster_level,
            preserve_default_ignorables,
            args.verify,
        )
        run1, run2, failure = run_pair(command, env, args.timeout)
        total_runs += 2

        case = Case(
            index=index,
            base_path=base_path,
            base_sha256=base_sha,
            font_path=font_path,
            text_path=text_path,
            text=text,
            direction=direction,
            language=language,
            features=feature_list,
            cluster_level=cluster_level,
            preserve_default_ignorables=preserve_default_ignorables,
            dropped_tables=tuple(dropped),
            modified_tables=tuple(modified),
            coverage=text_coverage,
        )

        for tag in dropped:
            dropped_counts[tag] = dropped_counts.get(tag, 0) + 1
        for tag in modified:
            modified_counts[tag] = modified_counts.get(tag, 0) + 1
        base_key = str(base_path)
        base_counts[base_key] = base_counts.get(base_key, 0) + 1
        direction_counts[direction] = direction_counts.get(direction, 0) + 1
        for key, value in text_coverage.items():
            if value:
                coverage_counts[key] += 1

        record = {
            "index": index,
            "base_font": base_key,
            "base_sha256": base_sha,
            "font_sha256": sha256_bytes(font_bytes),
            "font_size": len(font_bytes),
            "dropped_tables": list(dropped),
            "modified_tables": list(modified),
            "text": text,
            "text_escaped": escape_text(text),
            "text_utf8_hex": text.encode("utf-8").hex(),
            "direction": direction,
            "language": language,
            "features": list(feature_list),
            "cluster_level": cluster_level,
            "preserve_default_ignorables": preserve_default_ignorables,
            "coverage": text_coverage,
            "run1_returncode": run1.returncode,
            "run2_returncode": run2.returncode,
            "run1_stdout": run1.stdout.decode("utf-8", "replace"),
            "run2_stdout": run2.stdout.decode("utf-8", "replace"),
            "same_output": run1.stdout == run2.stdout,
            "run1_elapsed": round(run1.elapsed, 4),
            "run2_elapsed": round(run2.elapsed, 4),
            "failure": failure.kind if failure else None,
        }
        with cases_path.open("a", encoding="utf-8") as cases_file:
            cases_file.write(json.dumps(record, ensure_ascii=True) + "\n")

        if failure:
            stats[failure.kind] += 1
            minimized, minimized_text, minimized_meta = minimize_failure(
                case,
                failure,
                mutant,
                hb_shape,
                env,
                args.timeout,
                args.verify,
                out_dir,
            )
            failures.append({
                "case": index,
                "base_font": base_key,
                "kind": failure.kind,
                "detail": failure.detail,
                "original_text": escape_text(text),
                "original_dropped_tables": list(dropped),
                "minimized": minimized_meta,
                "minimized_text": escape_text(minimized_text),
                "minimized_tables": [tag_name(tag) for tag, _ in minimized.tables],
                "failure_dir": str(out_dir / "failures" / f"case-{index:03d}"),
            })
            print(
                f"FAIL case-{index:03d} {failure.kind}: {failure.detail}",
                file=sys.stderr,
            )
        elif not args.keep_fonts:
            font_path.unlink(missing_ok=True)
            text_path.unlink(missing_ok=True)

        if (index + 1) % 20 == 0 or index + 1 == args.cases:
            print(
                f"progress: {index + 1}/{args.cases} cases, "
                f"{len(failures)} failures",
                file=sys.stderr,
            )

    elapsed = time.time() - started
    result = {
        "cases": args.cases,
        "runs": total_runs,
        "seed": args.seed,
        "hb_shape": str(hb_shape),
        "hb_shape_version": hb_shape_version(hb_shape, env),
        "sanitizers": "address,undefined,leak",
        "verify": args.verify,
        "duration_seconds": round(elapsed, 3),
        "failures": len(failures),
        "stats": stats,
        "coverage": {
            "text_features": coverage_counts,
            "dropped_tables": dict(sorted(dropped_counts.items())),
            "modified_tables": dict(sorted(modified_counts.items())),
            "base_fonts": dict(sorted(base_counts.items())),
            "unique_fonts": len(seen_font_hashes),
        },
        "counterexamples": failures,
    }

    (out_dir / "summary.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )

    report = [
        "# Randomized shaping property test",
        "",
        f"- Seed: `{args.seed}`",
        f"- Cases: `{args.cases}` (`{total_runs}` fresh hb-shape processes)",
        f"- hb-shape: `{hb_shape}`",
        f"- Version: `{result['hb_shape_version']}`",
        "- Sanitizers: AddressSanitizer, UndefinedBehaviorSanitizer, "
        "LeakSanitizer",
        f"- Duration: `{elapsed:.1f}s`",
        "",
        "## Result",
        "",
        "| Property | Failures |",
        "|---|---:|",
        f"| Out-of-bounds / use-after-free | {stats['out_of_bounds']} |",
        f"| Leaks | {stats['leak']} |",
        f"| UBSan | {stats['ubsan']} |",
        f"| Other ASan | {stats['asan']} |",
        (
            f"| Buffer verify | {stats['verify']} |"
            if args.verify else "| Buffer verify | not run |"
        ),
        f"| Timeout | {stats['timeout']} |",
        f"| Signal / crash | {stats['crash']} |",
        f"| Other nonzero exit | {stats['exit']} |",
        f"| Nondeterministic glyph output | {stats['nondeterministic']} |",
        "",
        "## Coverage",
        "",
        f"- Combining marks in text: `{coverage_counts['combining']}/{args.cases}`",
        f"- RTL script codepoints in text: `{coverage_counts['rtl']}/{args.cases}`",
        f"- ZWJ in text: `{coverage_counts['zwj']}/{args.cases}`",
        f"- ZWNJ in text: `{coverage_counts['zwnj']}/{args.cases}`",
        f"- Distinct base fonts: `{len(base_counts)}`",
        f"- Distinct generated fonts: `{len(seen_font_hashes)}/{args.cases}`",
        f"- Distinct tables forced missing: `{len(dropped_counts)}`",
        f"- Table drops: `{sum(dropped_counts.values())}`; "
        f"damaged tables: `{sum(modified_counts.values())}`",
        "- Directions: "
        + ", ".join(
            f"`{name}={count}`"
            for name, count in sorted(direction_counts.items())
        ),
        "",
        "## Counterexamples",
        "",
    ]
    if not failures:
        report.append(
            f"None. All {args.cases} font/text combinations completed twice with no "
            "sanitizer report, leak, timeout, nonzero exit, or glyph-sequence "
            "mismatch."
        )
    else:
        for failure in failures:
            minimized = failure["minimized"]
            report.extend([
                f"### Case {failure['case']:03d}: `{failure['kind']}`",
                "",
                f"- Detail: `{failure['detail']}`",
                f"- Minimized font: `{failure['failure_dir']}/font-minimized.ttf` "
                f"(`{minimized['font_sha256'][:16]}`, "
                f"`{minimized['font_size']}` bytes, tables "
                f"`{', '.join(minimized['font_tables'])}`)",
                f"- Minimized text: `\"{minimized['text']}\"`",
                f"- Reproduced after minimization: `{minimized['reproduced']}`",
                "- Command:",
                "",
                "```sh",
                " ".join(minimized["command"]),
                "```",
                "",
            ])
    (out_dir / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")

    print(json.dumps({
        "cases": args.cases,
        "runs": total_runs,
        "duration_seconds": round(elapsed, 3),
        "failures": len(failures),
        "stats": stats,
        "coverage": {
            "combining": coverage_counts["combining"],
            "rtl": coverage_counts["rtl"],
            "zwj": coverage_counts["zwj"],
            "zwnj": coverage_counts["zwnj"],
        },
        "report": str(out_dir / "report.md"),
    }, indent=2, ensure_ascii=True))

    for failure in failures:
        print(
            f"COUNTEREXAMPLE case-{failure['case']:03d}: "
            f"{failure['kind']}: {failure['detail']}\n"
            f"  font: {failure['failure_dir']}/font-minimized.ttf\n"
            f"  text: \"{failure['minimized_text']}\"\n"
            f"  command: {' '.join(failure['minimized']['command'])}",
            file=sys.stderr,
        )

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
