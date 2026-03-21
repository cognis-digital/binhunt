"""Smoke tests for BINHUNT. No network. Self-contained sample generation."""
import importlib.util
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from binhunt import core, TOOL_NAME, TOOL_VERSION  # noqa: E402
from binhunt.cli import main  # noqa: E402

DEMO_DIR = os.path.join(ROOT, "demos", "01-basic")
SAMPLE = os.path.join(DEMO_DIR, "sample.elf")


def _load_make_sample():
    spec = importlib.util.spec_from_file_location(
        "make_sample", os.path.join(DEMO_DIR, "make_sample.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def sample_path():
    if not os.path.exists(SAMPLE):
        mod = _load_make_sample()
        with open(SAMPLE, "wb") as fh:
            fh.write(mod.build_sample_elf())
    return SAMPLE


def test_metadata():
    assert TOOL_NAME == "binhunt"
    assert TOOL_VERSION.count(".") == 2


def test_entropy_bounds():
    assert core.shannon_entropy(b"") == 0.0
    assert core.shannon_entropy(b"\x00" * 1000) == 0.0
    # all 256 byte values equally likely -> 8 bits/byte
    assert abs(core.shannon_entropy(bytes(range(256))) - 8.0) < 1e-6


def test_detect_format(sample_path):
    with open(sample_path, "rb") as fh:
        data = fh.read()
    assert core.detect_format(data) == "ELF"
    assert core.detect_format(b"MZ\x00\x00") == "PE"
    assert core.detect_format(b"garbage") == "unknown"


def test_scan_parses_elf_sections(sample_path):
    r = core.scan_file(sample_path)
    assert r.fmt == "ELF"
    assert r.arch == "x86-64"
    names = {s["name"] for s in r.sections}
    assert ".text" in names
    assert ".packed" in names
    # the .packed section is high-entropy by construction
    packed = next(s for s in r.sections if s["name"] == ".packed")
    assert packed["entropy"] > 7.4
    # which should produce a SECTION_ENTROPY finding
    assert any(f.id == "SECTION_ENTROPY" for f in r.findings)
    assert r.max_severity() in ("medium", "high", "critical")


def test_fuzzy_similarity_self(sample_path):
    with open(sample_path, "rb") as fh:
        data = fh.read()
    fp = core.fuzzy_fingerprint(data)
    assert core.fuzzy_similarity(fp, fp) == 1.0
    mutated = data[:-1] + bytes([data[-1] ^ 0xFF])
    fp2 = core.fuzzy_fingerprint(mutated)
    # one block changes -> similarity < 1 but > 0
    sim = core.fuzzy_similarity(fp, fp2)
    assert 0.0 < sim < 1.0


def test_baseline_match_and_tamper(sample_path, tmp_path):
    base = core.build_baseline([sample_path])
    bpath = tmp_path / "base.json"
    with open(bpath, "w", encoding="utf-8") as fh:
        import json
        json.dump(base, fh)

    # unmodified -> MATCH / info
    r = core.scan_file(sample_path)
    findings = core.diff_baseline(r, base)
    assert any(f.id == "MATCH" for f in findings)
    assert all(f.severity == "info" for f in findings)

    # tamper: flip a byte in the .text section and write a modded copy
    with open(sample_path, "rb") as fh:
        data = bytearray(fh.read())
    data[64] ^= 0xFF  # first byte of .text
    modded = tmp_path / "sample.elf"  # same basename -> same baseline key
    with open(modded, "wb") as fh:
        fh.write(data)
    r2 = core.scan_file(str(modded))
    findings2 = core.diff_baseline(r2, base)
    assert any(f.id == "HASH_MISMATCH" and f.severity == "critical"
               for f in findings2)


def test_packer_signature_detection():
    # craft bytes containing a UPX marker; detect_packers scans head/tail
    blob = b"MZ" + b"\x00" * 100 + b"UPX!" + b"\x00" * 100
    packers = core.detect_packers(blob, [])
    assert "UPX" in packers


def test_cli_scan_exit_code(sample_path, capsys):
    # medium finding present -> exit 2
    rc = main(["scan", sample_path])
    out = capsys.readouterr().out
    assert "sha256" in out
    assert rc == 2


def test_cli_json_format(sample_path, capsys):
    rc = main(["--format", "json", "scan", sample_path])
    out = capsys.readouterr().out
    import json
    payload = json.loads(out)
    assert payload["fmt"] == "ELF"
    assert "max_severity" in payload
    assert rc == 2


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["--version"])
    assert ei.value.code == 0
    out = capsys.readouterr().out
    assert "binhunt" in out
