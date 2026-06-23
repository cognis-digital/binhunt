"""CLI tests for binhunt: scan/baseline/diff across table/json/sarif/csv,
exit codes, and the --fail-on gate. No network; stdlib only.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from binhunt.cli import main, build_parser  # noqa: E402
from tests.test_core_extra import _make_elf, LOW, HIGH  # noqa: E402


@pytest.fixture
def clean_elf(tmp_path):
    # low-entropy ELF -> no medium+ findings
    data = _make_elf([(".text", LOW[:64]), (".data", LOW[:128])])
    p = tmp_path / "clean.elf"
    p.write_bytes(data)
    return str(p)


@pytest.fixture
def packed_elf(tmp_path):
    data = _make_elf([(".text", LOW[:64]), (".packed", HIGH)])
    p = tmp_path / "packed.elf"
    p.write_bytes(data)
    return str(p)


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

def test_scan_table_clean_exit0(clean_elf, capsys):
    rc = main(["scan", clean_elf])
    out = capsys.readouterr().out
    assert "format    : ELF" in out
    assert "verdict   : INFO" in out
    assert rc == 0


def test_scan_table_packed_exit2(packed_elf, capsys):
    rc = main(["scan", packed_elf])
    out = capsys.readouterr().out
    assert "sha256" in out
    assert "SECTION_ENTROPY" in out
    assert rc == 2


def test_scan_json(packed_elf, capsys):
    rc = main(["--format", "json", "scan", packed_elf])
    payload = json.loads(capsys.readouterr().out)
    assert payload["fmt"] == "ELF"
    assert payload["arch"] == "x86-64"
    assert len(payload["sha256"]) == 64
    assert payload["max_severity"] in ("medium", "high", "critical")
    assert rc == 2


def test_scan_sarif(packed_elf, capsys):
    rc = main(["--format", "sarif", "scan", packed_elf])
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "binhunt"
    assert len(sarif["runs"][0]["results"]) >= 1
    assert rc == 2


def test_scan_csv(packed_elf, capsys):
    rc = main(["--format", "csv", "scan", packed_elf])
    out = capsys.readouterr().out
    lines = out.strip().splitlines()
    assert lines[0] == "path,id,severity,title,detail"
    assert len(lines) >= 2
    assert rc == 2


def test_scan_missing_file_exit1(capsys):
    rc = main(["scan", "/no/such/file.bin"])
    err = capsys.readouterr().err
    assert "error" in err.lower()
    assert rc == 1


# ---------------------------------------------------------------------------
# --fail-on gate
# ---------------------------------------------------------------------------

def test_fail_on_high_ignores_medium(packed_elf, capsys):
    # packed sample's worst finding is medium; --fail-on high -> exit 0
    rc = main(["--fail-on", "high", "scan", packed_elf])
    capsys.readouterr()
    assert rc == 0


def test_fail_on_low_trips_on_medium(packed_elf, capsys):
    rc = main(["--fail-on", "low", "scan", packed_elf])
    capsys.readouterr()
    assert rc == 2


def test_fail_on_default_is_medium(packed_elf, capsys):
    rc = main(["scan", packed_elf])
    capsys.readouterr()
    assert rc == 2


# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------

def test_baseline_to_stdout(clean_elf, capsys):
    rc = main(["baseline", clean_elf])
    payload = json.loads(capsys.readouterr().out)
    assert payload["binhunt_baseline"] == 1
    assert "clean.elf" in payload["entries"]
    assert rc == 0


def test_baseline_to_file(clean_elf, tmp_path, capsys):
    out = tmp_path / "b.json"
    rc = main(["baseline", clean_elf, "-o", str(out)])
    msg = capsys.readouterr().out
    assert "wrote baseline" in msg
    assert "1 entry" in msg
    assert rc == 0
    saved = json.loads(out.read_text())
    assert "clean.elf" in saved["entries"]


def test_baseline_multiple_entries(clean_elf, packed_elf, tmp_path, capsys):
    out = tmp_path / "b.json"
    rc = main(["baseline", clean_elf, packed_elf, "-o", str(out)])
    msg = capsys.readouterr().out
    assert "2 entries" in msg
    assert rc == 0


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

def test_diff_match_exit0(clean_elf, tmp_path, capsys):
    base = tmp_path / "b.json"
    main(["baseline", clean_elf, "-o", str(base)])
    capsys.readouterr()
    rc = main(["diff", clean_elf, "--baseline", str(base)])
    out = capsys.readouterr().out
    assert "MATCH" in out
    assert rc == 0


def test_diff_tamper_exit2(clean_elf, tmp_path, capsys):
    base = tmp_path / "b.json"
    main(["baseline", clean_elf, "-o", str(base)])
    capsys.readouterr()
    # tamper a copy with the same basename
    data = bytearray(open(clean_elf, "rb").read())
    data[64] ^= 0xFF
    tdir = tmp_path / "sub"
    tdir.mkdir()
    mod = tdir / "clean.elf"
    mod.write_bytes(data)
    rc = main(["diff", str(mod), "--baseline", str(base)])
    out = capsys.readouterr().out
    assert "HASH_MISMATCH" in out
    assert rc == 2


def test_diff_json(clean_elf, tmp_path, capsys):
    base = tmp_path / "b.json"
    main(["baseline", clean_elf, "-o", str(base)])
    capsys.readouterr()
    rc = main(["--format", "json", "diff", clean_elf, "--baseline", str(base)])
    payload = json.loads(capsys.readouterr().out)
    assert "findings" in payload
    assert "max_severity" in payload
    assert rc == 0


def test_diff_sarif(clean_elf, tmp_path, capsys):
    base = tmp_path / "b.json"
    main(["baseline", clean_elf, "-o", str(base)])
    capsys.readouterr()
    rc = main(["--format", "sarif", "diff", clean_elf, "--baseline", str(base)])
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert rc == 0


def test_diff_bad_baseline_json_exit1(clean_elf, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not valid json")
    rc = main(["diff", clean_elf, "--baseline", str(bad)])
    err = capsys.readouterr().err
    assert "invalid baseline" in err.lower()
    assert rc == 1


def test_diff_missing_baseline_file_exit1(clean_elf, capsys):
    rc = main(["diff", clean_elf, "--baseline", "/no/such/baseline.json"])
    capsys.readouterr()
    assert rc == 1


# ---------------------------------------------------------------------------
# parser / version / help
# ---------------------------------------------------------------------------

def test_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["--version"])
    assert ei.value.code == 0
    assert "binhunt" in capsys.readouterr().out


def test_no_command_prints_help_exit1(capsys):
    rc = main([])
    out = capsys.readouterr().out
    assert "usage" in out.lower() or "command" in out.lower()
    assert rc == 1


def test_parser_format_choices():
    p = build_parser()
    ns = p.parse_args(["--format", "sarif", "scan", "x"])
    assert ns.format == "sarif"
    ns2 = p.parse_args(["--fail-on", "critical", "scan", "x"])
    assert ns2.fail_on == "critical"


def test_parser_has_mcp_subcommand():
    p = build_parser()
    ns = p.parse_args(["mcp"])
    assert ns.cmd == "mcp"


def test_invalid_format_rejected():
    p = build_parser()
    with pytest.raises(SystemExit):
        p.parse_args(["--format", "xml", "scan", "x"])
