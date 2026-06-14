"""Hardening tests — edge cases, bad input, and error paths.

These tests verify that binhunt fails gracefully with clear messages
and correct exit codes rather than raising raw tracebacks.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from binhunt import core  # noqa: E402
from binhunt.cli import main  # noqa: E402


# ---------------------------------------------------------------------------
# core.fuzzy_similarity — bad / degenerate fingerprint strings
# ---------------------------------------------------------------------------

def test_fuzzy_similarity_non_integer_block_count():
    """fuzzy_similarity must return 0.0, not raise ValueError, on non-int counts."""
    assert core.fuzzy_similarity("notanint:abcd1234", "notanint:abcd1234") == 0.0


def test_fuzzy_similarity_zero_blocks():
    """'0:' fingerprint (empty file) must not divide by zero."""
    assert core.fuzzy_similarity("0:", "0:") == 0.0


def test_fuzzy_similarity_mismatched_counts():
    """Block counts that differ must return 0.0."""
    a = "2:" + "a" * 16
    b = "3:" + "a" * 24
    assert core.fuzzy_similarity(a, b) == 0.0


# ---------------------------------------------------------------------------
# core.scan_file — missing / empty files
# ---------------------------------------------------------------------------

def test_scan_file_missing_raises():
    """scan_file must raise FileNotFoundError for a non-existent path."""
    with pytest.raises(FileNotFoundError):
        core.scan_file("/nonexistent/path/to/nowhere.exe")


def test_scan_file_empty_returns_info_finding(tmp_path):
    """scan_file on a zero-byte file must return EMPTY_FILE info finding."""
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    result = core.scan_file(str(empty))
    assert result.size == 0
    assert result.fmt == "unknown"
    assert any(f.id == "EMPTY_FILE" for f in result.findings)
    # empty file is info-only — no suspicious findings
    assert result.max_severity() == "info"


def test_scan_file_directory_raises(tmp_path):
    """scan_file on a directory path must raise ValueError."""
    with pytest.raises(ValueError):
        core.scan_file(str(tmp_path))


# ---------------------------------------------------------------------------
# core.load_baseline — structural validation
# ---------------------------------------------------------------------------

def test_load_baseline_missing_file():
    """load_baseline must raise FileNotFoundError for a missing path."""
    with pytest.raises(FileNotFoundError):
        core.load_baseline("/no/such/baseline.json")


def test_load_baseline_bad_json(tmp_path):
    """load_baseline must raise json.JSONDecodeError for malformed JSON."""
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not json }", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        core.load_baseline(str(bad))


def test_load_baseline_wrong_type(tmp_path):
    """load_baseline must raise ValueError when the JSON root is a list, not a dict."""
    f = tmp_path / "list.json"
    f.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        core.load_baseline(str(f))


def test_load_baseline_missing_entries_key(tmp_path):
    """load_baseline must raise ValueError when 'entries' key is absent."""
    f = tmp_path / "noentries.json"
    f.write_text(json.dumps({"binhunt_baseline": 1}), encoding="utf-8")
    with pytest.raises(ValueError, match="entries"):
        core.load_baseline(str(f))


# ---------------------------------------------------------------------------
# core.build_baseline — empty paths
# ---------------------------------------------------------------------------

def test_build_baseline_empty_paths():
    """build_baseline must raise ValueError when called with no paths."""
    with pytest.raises(ValueError, match="at least one"):
        core.build_baseline([])


# ---------------------------------------------------------------------------
# core.diff_baseline — non-dict baseline argument
# ---------------------------------------------------------------------------

def test_diff_baseline_non_dict_raises(tmp_path):
    """diff_baseline must raise TypeError when passed a non-dict baseline."""
    f = tmp_path / "dummy.bin"
    f.write_bytes(b"\x7fELF" + b"\x00" * 60)
    result = core.scan_file(str(f))
    with pytest.raises(TypeError, match="dict"):
        core.diff_baseline(result, [1, 2, 3])


# ---------------------------------------------------------------------------
# CLI — exit codes for bad input
# ---------------------------------------------------------------------------

def test_cli_scan_missing_file(capsys):
    """CLI scan on a missing file must print to stderr and return exit code 1."""
    rc = main(["scan", "/nonexistent/nowhere.exe"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "error" in err.lower()


def test_cli_scan_empty_file(tmp_path, capsys):
    """CLI scan on an empty file must succeed (exit 0) with an info result."""
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    rc = main(["scan", str(empty)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "EMPTY_FILE" in out or "empty" in out.lower()


def test_cli_diff_malformed_baseline_json(tmp_path, capsys):
    """CLI diff with malformed JSON baseline must print error to stderr, exit 1."""
    target = tmp_path / "target.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{{{ broken", encoding="utf-8")
    rc = main(["diff", str(target), "--baseline", str(bad_json)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "error" in err.lower()


def test_cli_diff_wrong_baseline_structure(tmp_path, capsys):
    """CLI diff with valid JSON but wrong baseline shape must exit 1 with a message."""
    target = tmp_path / "target.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"not_a_baseline": True}), encoding="utf-8")
    rc = main(["diff", str(target), "--baseline", str(wrong)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "error" in err.lower()


def test_cli_no_subcommand(capsys):
    """CLI with no subcommand must print help and return exit code 1."""
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 1
    assert "scan" in out  # help text mentions the scan subcommand
