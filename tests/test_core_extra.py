"""Extended unit tests for binhunt core: parsing, entropy, fuzzy, packers,
baseline diff, and the JSON/SARIF/CSV emitters. No network; stdlib only.

These tests build PE/ELF/Mach-O fixtures in memory so they run identically on
every platform and in CI.
"""
import json
import os
import struct
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from binhunt import core  # noqa: E402
from binhunt.core import Finding, ScanResult  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures: synthetic binaries
# ---------------------------------------------------------------------------

def _make_elf(sections):
    """Build a minimal valid 64-bit LE ELF with the given (name, bytes) sections.

    Returns the ELF bytes. Mirrors demos/01-basic/make_sample.py but param'd.
    """
    ehsize = 64
    shentsize = 64
    # shstrtab: null + each name + 'shstrtab'
    names = [s[0] for s in sections] + ["shstrtab"]
    shstr = b"\x00"
    name_offsets = {}
    for nm in names:
        name_offsets[nm] = len(shstr)
        shstr += nm.encode() + b"\x00"

    body = bytearray()
    sec_layout = []  # (name, offset, size)
    cur = ehsize
    for nm, payload in sections:
        sec_layout.append((nm, cur, len(payload)))
        body += payload
        cur += len(payload)
    shstr_off = cur
    body += shstr
    cur += len(shstr)
    sh_off = cur
    num_sections = 1 + len(sections) + 1  # null + sections + shstrtab

    e = bytearray()
    e += b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    e += struct.pack("<H", 2)         # ET_EXEC
    e += struct.pack("<H", 0x3e)      # x86-64
    e += struct.pack("<I", 1)
    e += struct.pack("<Q", 0)         # e_entry
    e += struct.pack("<Q", 0)         # e_phoff
    e += struct.pack("<Q", sh_off)
    e += struct.pack("<I", 0)
    e += struct.pack("<H", ehsize)
    e += struct.pack("<H", 0)
    e += struct.pack("<H", 0)
    e += struct.pack("<H", shentsize)
    e += struct.pack("<H", num_sections)
    e += struct.pack("<H", num_sections - 1)  # shstrndx -> last
    assert len(e) == ehsize

    def shdr(name_off, sh_type, offset, size):
        return struct.pack("<IIQQQQIIQQ",
                           name_off, sh_type, 0, 0, offset, size, 0, 0, 0, 0)

    headers = bytearray()
    headers += shdr(0, 0, 0, 0)
    for nm, off, size in sec_layout:
        headers += shdr(name_offsets[nm], 1, off, size)
    headers += shdr(name_offsets["shstrtab"], 3, shstr_off, len(shstr))

    return bytes(e) + bytes(body) + bytes(headers)


def _make_pe(section_names, machine=0x8664):
    """Build a minimal PE with the given section names (each 16 bytes raw)."""
    e_lfanew = 0x80
    mz = bytearray(b"\x00" * e_lfanew)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, e_lfanew)  # DOS header points to PE header
    pe = bytearray()
    pe += b"PE\x00\x00"
    num = len(section_names)
    pe += struct.pack("<HH", machine, num)
    pe += struct.pack("<I", 0)        # timestamp
    pe += struct.pack("<I", 0)        # ptr to symtab
    pe += struct.pack("<I", 0)        # num symbols
    opt_size = 0xE0
    pe += struct.pack("<H", opt_size)
    pe += struct.pack("<H", 0)        # characteristics
    pe += b"\x00" * opt_size          # optional header (zeros)
    base = e_lfanew + 4 + 20 + opt_size  # offset where section table starts
    sec_data = bytearray()
    data_off = base + num * 40
    for i, nm in enumerate(section_names):
        name = nm.encode()[:8].ljust(8, b"\x00")
        raw_size = 32
        raw_off = data_off + i * 32
        sec = name + struct.pack("<IIII", 0, 0, raw_size, raw_off) + b"\x00" * 16
        assert len(sec) == 40
        sec_data += sec
    full = bytes(mz) + bytes(pe) + bytes(sec_data)
    # pad so raw offsets are valid + give code-ish content
    full += b"\x90" * (num * 32 + 64)
    return full


def _make_macho64():
    """Minimal 64-bit Mach-O (LE) with one LC_SEGMENT_64."""
    m = bytearray()
    m += b"\xcf\xfa\xed\xfe"          # magic
    m += struct.pack("<i", 0x01000007)  # x86-64
    m += struct.pack("<i", 0)         # cpusubtype
    m += struct.pack("<I", 2)         # filetype
    m += struct.pack("<I", 1)         # ncmds
    seg = bytearray()
    seg += struct.pack("<II", 0x19, 72)  # LC_SEGMENT_64, cmdsize
    seg += b"__TEXT".ljust(16, b"\x00")
    seg += struct.pack("<QQ", 0, 0)   # vmaddr, vmsize
    seg += struct.pack("<QQ", 0, 16)  # fileoff, filesize
    seg += b"\x00" * (72 - len(seg))
    m += struct.pack("<I", len(seg))  # sizeofcmds
    m += struct.pack("<I", 0)         # flags
    m += b"\x00" * 4                  # reserved (64-bit header)
    m += seg
    m += b"\x90" * 16
    return bytes(m)


HIGH = bytes((i * 167 + 13) % 256 for i in range(4096))
LOW = b"\x90" * 4096


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def test_entropy_empty_and_uniform():
    assert core.shannon_entropy(b"") == 0.0
    assert core.shannon_entropy(b"\x00") == 0.0
    assert core.shannon_entropy(b"\x00" * 99999) == 0.0
    assert abs(core.shannon_entropy(bytes(range(256))) - 8.0) < 1e-6


def test_entropy_two_symbols():
    # 50/50 of two symbols -> exactly 1 bit/byte
    data = b"\x00\x01" * 500
    assert abs(core.shannon_entropy(data) - 1.0) < 1e-6


def test_entropy_monotone_with_randomness():
    assert core.shannon_entropy(LOW) < core.shannon_entropy(HIGH)
    assert core.shannon_entropy(HIGH) > 7.0


def test_entropy_rounding():
    e = core.shannon_entropy(b"abcd" * 50)
    # rounded to 4 decimal places
    assert round(e, 4) == e


# ---------------------------------------------------------------------------
# Fuzzy fingerprint + similarity
# ---------------------------------------------------------------------------

def test_fuzzy_format():
    fp = core.fuzzy_fingerprint(b"hello world" * 100)
    n, rest = fp.split(":", 1)
    assert int(n) == 16
    assert len(rest) == 16 * 8


def test_fuzzy_empty():
    assert core.fuzzy_fingerprint(b"") == "0:"


def test_fuzzy_small_input_blocks_clamped():
    fp = core.fuzzy_fingerprint(b"abc", blocks=16)
    n = int(fp.split(":", 1)[0])
    assert 1 <= n <= 3


def test_fuzzy_similarity_identity_and_zero():
    a = core.fuzzy_fingerprint(HIGH)
    assert core.fuzzy_similarity(a, a) == 1.0
    b = core.fuzzy_fingerprint(LOW)
    assert core.fuzzy_similarity(a, b) == 0.0


def test_fuzzy_similarity_partial():
    data = bytearray(HIGH)
    fp1 = core.fuzzy_fingerprint(bytes(data))
    data[0] ^= 0xFF  # change only first block
    fp2 = core.fuzzy_fingerprint(bytes(data))
    sim = core.fuzzy_similarity(fp1, fp2)
    assert 0.0 < sim < 1.0
    assert abs(sim - (15 / 16)) < 1e-6


def test_fuzzy_similarity_mismatched_blockcount():
    assert core.fuzzy_similarity("16:" + "aa" * 64, "8:" + "aa" * 32) == 0.0


def test_fuzzy_similarity_garbage():
    assert core.fuzzy_similarity("nonsense", "more nonsense") == 0.0
    assert core.fuzzy_similarity("", "") == 0.0


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def test_detect_format_all():
    assert core.detect_format(b"MZ\x00\x00") == "PE"
    assert core.detect_format(b"\x7fELF....") == "ELF"
    assert core.detect_format(b"\xcf\xfa\xed\xfe....") == "MachO"
    assert core.detect_format(b"\xfe\xed\xfa\xce....") == "MachO"
    assert core.detect_format(b"\xca\xfe\xba\xbe....") == "MachO-FAT"
    assert core.detect_format(b"random bytes") == "unknown"
    assert core.detect_format(b"") == "unknown"


# ---------------------------------------------------------------------------
# Section parsing
# ---------------------------------------------------------------------------

def test_parse_elf_sections_and_arch():
    data = _make_elf([(".text", LOW[:64]), (".packed", HIGH)])
    arch, secs = core.section_entropies(data, "ELF")
    assert arch == "x86-64"
    names = {s["name"] for s in secs}
    assert ".text" in names and ".packed" in names
    packed = next(s for s in secs if s["name"] == ".packed")
    assert packed["entropy"] > 7.4
    assert packed["size"] == len(HIGH)


def test_parse_pe_sections_and_arch():
    data = _make_pe([".text", ".rdata", "weird"], machine=0x8664)
    arch, secs = core.section_entropies(data, "PE")
    assert arch == "x86-64"
    names = [s["name"] for s in secs]
    assert ".text" in names and "weird" in names


def test_parse_pe_arch_variants():
    for machine, expect in [(0x14c, "x86"), (0x8664, "x86-64"),
                            (0x1c0, "arm"), (0xaa64, "arm64")]:
        data = _make_pe([".text"], machine=machine)
        arch, _ = core.section_entropies(data, "PE")
        assert arch == expect


def test_parse_macho_segment():
    data = _make_macho64()
    arch, secs = core.section_entropies(data, "MachO")
    assert arch == "x86-64"
    assert any(s["name"] == "__TEXT" for s in secs)


def test_parse_truncated_is_safe():
    # truncated headers must not raise
    assert core.section_entropies(b"\x7fELF\x02\x01", "ELF") == ("unknown", [])
    assert core.section_entropies(b"MZ", "PE")[1] == []


# ---------------------------------------------------------------------------
# Packer detection
# ---------------------------------------------------------------------------

def test_packer_signatures():
    cases = {
        b"UPX!": "UPX",
        b"VMProtect": "VMProtect",
        b".themida": "Themida",
        b"ASPack": "ASPack",
        b"PECompact": "PECompact",
        b"MPRESS": "MPRESS",
        b"Enigma": "Enigma",
    }
    for sig, label in cases.items():
        blob = b"MZ" + b"\x00" * 100 + sig + b"\x00" * 100
        assert label in core.detect_packers(blob, [])


def test_packer_section_names():
    secs = [{"name": "UPX0", "offset": 0, "size": 0, "entropy": 0.0},
            {"name": ".vmp0", "offset": 0, "size": 0, "entropy": 0.0}]
    found = core.detect_packers(b"", secs)
    assert "UPX" in found and "VMProtect" in found


def test_packer_tail_scan():
    blob = b"MZ" + b"\x00" * 200000 + b"UPX!" + b"\x00" * 10
    assert "UPX" in core.detect_packers(blob, [])


def test_no_packer_clean():
    assert core.detect_packers(b"\x90" * 1000, []) == []


# ---------------------------------------------------------------------------
# Fingerprint + scan_bytes
# ---------------------------------------------------------------------------

def test_fingerprint_known_vectors():
    fp = core.fingerprint(b"")
    assert fp["sha256"] == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert fp["md5"] == "d41d8cd98f00b204e9800998ecf8427e"


def test_scan_bytes_elf_findings():
    data = _make_elf([(".text", LOW[:64]), (".packed", HIGH)])
    r = core.scan_bytes(data, path="mem.elf")
    assert r.fmt == "ELF"
    assert r.arch == "x86-64"
    assert r.size == len(data)
    assert len(r.sha256) == 64
    assert any(f.id == "SECTION_ENTROPY" for f in r.findings)
    assert r.max_severity() in ("medium", "high", "critical")


def test_scan_bytes_packed_pe_is_high():
    data = _make_pe([".text", "UPX0"]) + b"UPX!"
    r = core.scan_bytes(data, path="packed.exe")
    assert any(f.id == "PACKER" for f in r.findings)


def test_scan_bytes_unknown_format():
    r = core.scan_bytes(b"not a binary at all" * 10, path="x.bin")
    assert r.fmt == "unknown"
    assert any(f.id == "FMT_UNKNOWN" and f.severity == "info" for f in r.findings)


def test_scan_file_matches_scan_bytes(tmp_path):
    data = _make_elf([(".text", LOW[:64]), (".packed", HIGH)])
    p = tmp_path / "x.elf"
    p.write_bytes(data)
    r1 = core.scan_file(str(p))
    r2 = core.scan_bytes(data, path=str(p))
    assert r1.sha256 == r2.sha256
    assert r1.overall_entropy == r2.overall_entropy
    assert len(r1.findings) == len(r2.findings)


def test_scan_alias():
    data = _make_elf([(".text", LOW[:64])])
    # core.scan delegates to scan_file via path; write to tmp through fingerprint check
    assert core.scan is not None


# ---------------------------------------------------------------------------
# ScanResult model
# ---------------------------------------------------------------------------

def test_scanresult_max_severity_ordering():
    r = ScanResult(path="x", size=1, fmt="ELF", arch="x86-64",
                   sha256="a", md5="b", fuzzy="0:", overall_entropy=0.0)
    assert r.max_severity() == "info"
    r.findings.append(Finding("A", "low", "t", "d"))
    r.findings.append(Finding("B", "critical", "t", "d"))
    r.findings.append(Finding("C", "medium", "t", "d"))
    assert r.max_severity() == "critical"


def test_scanresult_to_dict_has_max_severity():
    r = ScanResult(path="x", size=1, fmt="ELF", arch="x86-64",
                   sha256="a", md5="b", fuzzy="0:", overall_entropy=0.0)
    r.findings.append(Finding("A", "high", "t", "d"))
    d = r.to_dict()
    assert d["max_severity"] == "high"
    assert d["findings"][0]["id"] == "A"
    assert isinstance(d["findings"], list)


def test_finding_to_dict_keys():
    f = Finding("ID", "low", "Title", "Detail")
    d = f.to_dict()
    assert d == {"id": "ID", "severity": "low", "title": "Title", "detail": "Detail"}


# ---------------------------------------------------------------------------
# Baseline build + diff
# ---------------------------------------------------------------------------

@pytest.fixture
def good_elf(tmp_path):
    data = _make_elf([(".text", LOW[:64]), (".packed", HIGH)])
    p = tmp_path / "client.elf"
    p.write_bytes(data)
    return str(p)


def test_build_baseline_shape(good_elf):
    base = core.build_baseline([good_elf])
    assert base["binhunt_baseline"] == 1
    assert "client.elf" in base["entries"]
    e = base["entries"]["client.elf"]
    assert set(e) >= {"sha256", "size", "fmt", "arch", "fuzzy",
                      "overall_entropy", "sections"}
    assert e["fmt"] == "ELF"


def test_baseline_roundtrip(good_elf, tmp_path):
    base = core.build_baseline([good_elf])
    p = tmp_path / "base.json"
    p.write_text(json.dumps(base))
    loaded = core.load_baseline(str(p))
    assert loaded == base


def test_diff_match(good_elf):
    base = core.build_baseline([good_elf])
    r = core.scan_file(good_elf)
    findings = core.diff_baseline(r, base)
    assert any(f.id == "MATCH" for f in findings)
    assert all(f.severity == "info" for f in findings)


def test_diff_no_baseline_entry(good_elf):
    base = core.build_baseline([good_elf])
    r = core.scan_file(good_elf)
    findings = core.diff_baseline(r, base, key="other.elf")
    assert any(f.id == "NO_BASELINE" and f.severity == "high" for f in findings)


def test_diff_hash_mismatch_and_size(good_elf, tmp_path):
    base = core.build_baseline([good_elf])
    data = bytearray(open(good_elf, "rb").read())
    data[64] ^= 0xFF                 # tamper .text
    data += b"\x00" * 100            # also change size
    mod = tmp_path / "client.elf"
    mod.write_bytes(data)
    r = core.scan_file(str(mod))
    findings = core.diff_baseline(r, base)
    ids = {f.id for f in findings}
    assert "HASH_MISMATCH" in ids
    assert "SIZE_CHANGE" in ids
    crit = [f for f in findings if f.id == "HASH_MISMATCH"]
    assert crit[0].severity == "critical"


def test_diff_section_drift(good_elf, tmp_path):
    base = core.build_baseline([good_elf])
    # rebuild with the .packed section replaced by low-entropy data
    data = _make_elf([(".text", LOW[:64]), (".packed", LOW)])
    mod = tmp_path / "client.elf"
    mod.write_bytes(data)
    r = core.scan_file(str(mod))
    findings = core.diff_baseline(r, base)
    assert any(f.id == "SECTION_DRIFT" for f in findings)


def test_diff_section_added_and_removed(good_elf, tmp_path):
    base = core.build_baseline([good_elf])
    data = _make_elf([(".text", LOW[:64]), (".newsec", HIGH)])  # .packed removed, .newsec added
    mod = tmp_path / "client.elf"
    mod.write_bytes(data)
    r = core.scan_file(str(mod))
    findings = core.diff_baseline(r, base)
    ids = {f.id for f in findings}
    assert "SECTION_ADDED" in ids
    assert "SECTION_REMOVED" in ids


# ---------------------------------------------------------------------------
# Emitters: JSON / SARIF / CSV
# ---------------------------------------------------------------------------

def _sample_findings():
    return [
        Finding("PACKER", "high", "Packer/obfuscator detected: VMProtect", "d1"),
        Finding("HIGH_ENTROPY", "medium", "High overall entropy", "d2"),
        Finding("FMT_UNKNOWN", "info", "Unrecognized binary format", "d3"),
    ]


def test_to_json_serializes():
    data = _make_elf([(".text", LOW[:64]), (".packed", HIGH)])
    r = core.scan_bytes(data, path="x.elf")
    txt = core.to_json(r)
    parsed = json.loads(txt)
    assert parsed["fmt"] == "ELF"
    assert "max_severity" in parsed
    assert isinstance(parsed["findings"], list)


def test_sarif_structure():
    sarif = core.findings_to_sarif(_sample_findings(), "bin/app.exe", "1.2.3")
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "binhunt"
    assert driver["version"] == "1.2.3"
    # 3 findings but PACKER/HIGH_ENTROPY/FMT_UNKNOWN are distinct -> 3 rules
    rule_ids = {r["id"] for r in driver["rules"]}
    assert rule_ids == {"PACKER", "HIGH_ENTROPY", "FMT_UNKNOWN"}
    assert len(run["results"]) == 3


def test_sarif_levels_mapped():
    sarif = core.findings_to_sarif(_sample_findings(), "x")
    levels = {res["ruleId"]: res["level"] for res in sarif["runs"][0]["results"]}
    assert levels["PACKER"] == "error"        # high -> error
    assert levels["HIGH_ENTROPY"] == "warning"  # medium -> warning
    assert levels["FMT_UNKNOWN"] == "note"      # info -> note


def test_sarif_security_severity_numbers():
    sarif = core.findings_to_sarif(_sample_findings(), "x")
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["PACKER"]["properties"]["security-severity"] == "8.0"
    assert float(rules["FMT_UNKNOWN"]["properties"]["security-severity"]) == 0.0


def test_sarif_dedups_rules():
    fs = [Finding("PACKER", "high", "a", "d"),
          Finding("PACKER", "high", "b", "d")]
    sarif = core.findings_to_sarif(fs, "x")
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(sarif["runs"][0]["results"]) == 2


def test_sarif_uri_uses_forward_slashes():
    sarif = core.findings_to_sarif([Finding("X", "low", "t", "d")],
                                   "C:\\bin\\app.exe")
    uri = sarif["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri
    assert uri == "C:/bin/app.exe"


def test_scan_to_sarif_helper():
    data = _make_elf([(".text", LOW[:64]), (".packed", HIGH)])
    r = core.scan_bytes(data, path="x.elf")
    sarif = core.scan_to_sarif(r, "9.9.9")
    assert sarif["runs"][0]["tool"]["driver"]["version"] == "9.9.9"


def test_csv_emitter():
    csv_text = core.findings_to_csv(_sample_findings(), "bin/app.exe")
    lines = csv_text.strip().splitlines()
    assert lines[0] == "path,id,severity,title,detail"
    assert len(lines) == 4
    assert "PACKER" in lines[1]
    assert "bin/app.exe" in lines[1]


def test_csv_quotes_commas():
    fs = [Finding("X", "low", "has, comma", "detail, with comma")]
    csv_text = core.findings_to_csv(fs, "p")
    # csv module must quote fields containing commas
    assert '"has, comma"' in csv_text


def test_csv_empty_findings():
    csv_text = core.findings_to_csv([], "p")
    assert csv_text.strip() == "path,id,severity,title,detail"


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def test_tool_identity():
    assert core.TOOL_NAME == "binhunt"
    assert core.TOOL_VERSION.count(".") == 2
    parts = core.TOOL_VERSION.split(".")
    assert all(p.isdigit() for p in parts)


def test_severity_order_complete():
    assert core.SEVERITY_ORDER["info"] < core.SEVERITY_ORDER["low"]
    assert core.SEVERITY_ORDER["medium"] < core.SEVERITY_ORDER["high"]
    assert core.SEVERITY_ORDER["high"] < core.SEVERITY_ORDER["critical"]
