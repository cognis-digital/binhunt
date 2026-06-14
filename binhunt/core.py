"""BINHUNT core engine.

Real parsing/detection logic for PE, ELF and Mach-O executables:
  * cryptographic + fuzzy fingerprints
  * format / architecture detection
  * section parsing with per-section Shannon entropy
  * packer / obfuscation heuristics (section names, high entropy, signatures)
  * baseline build + diff to detect tampering / trojanized clients

Standard library only.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import struct
from dataclasses import dataclass, field, asdict
from typing import Optional

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

# Severity ranking for exit-code decisions.
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    id: str
    severity: str  # info|low|medium|high|critical
    title: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    path: str
    size: int
    fmt: str
    arch: str
    sha256: str
    md5: str
    fuzzy: str
    overall_entropy: float
    sections: list = field(default_factory=list)  # list[dict]
    findings: list = field(default_factory=list)   # list[Finding]

    def max_severity(self) -> str:
        sev = "info"
        for f in self.findings:
            if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(sev, 0):
                sev = f.severity
        return sev

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        d["max_severity"] = self.max_severity()
        return d


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8). High (>7.2) suggests packed/encrypted."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)


# ---------------------------------------------------------------------------
# Fuzzy fingerprint (block-hash, dependency-free)
# ---------------------------------------------------------------------------

def fuzzy_fingerprint(data: bytes, blocks: int = 16) -> str:
    """Coarse, alignment-tolerant fingerprint.

    Splits the file into N equal blocks and emits a short hash per block.
    Two files with the same fuzzy fingerprint blocks are byte-identical in
    those regions; comparing block lists localizes *where* a binary changed.
    """
    if not data:
        return "0:"
    blocks = max(1, min(blocks, len(data)))
    step = math.ceil(len(data) / blocks)
    parts = []
    for i in range(0, len(data), step):
        chunk = data[i:i + step]
        parts.append(hashlib.sha1(chunk).hexdigest()[:8])
    return f"{len(parts)}:" + "".join(parts)


def fuzzy_similarity(a: str, b: str) -> float:
    """Fraction of matching fuzzy blocks (0..1). Requires same block count."""
    try:
        na, ra = a.split(":", 1)
        nb, rb = b.split(":", 1)
    except ValueError:
        return 0.0
    if na != nb or not ra:
        return 0.0
    try:
        n = int(na)
    except ValueError:
        return 0.0
    if n <= 0:
        return 0.0
    ba = [ra[i:i + 8] for i in range(0, len(ra), 8)]
    bb = [rb[i:i + 8] for i in range(0, len(rb), 8)]
    if len(ba) != n or len(bb) != n:
        return 0.0
    same = sum(1 for x, y in zip(ba, bb) if x == y)
    return round(same / n, 4)


# ---------------------------------------------------------------------------
# Format detection + section parsing
# ---------------------------------------------------------------------------

def detect_format(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "MachO"
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return "MachO-FAT"
    return "unknown"


def _parse_pe(data: bytes):
    """Return (arch, [ (name, raw_offset, raw_size) ])."""
    sections = []
    arch = "unknown"
    try:
        if len(data) < 0x40:
            return arch, sections
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return arch, sections
        coff = e_lfanew + 4
        machine, num_sections = struct.unpack_from("<HH", data, coff)
        arch = {0x14c: "x86", 0x8664: "x86-64", 0x1c0: "arm",
                0xaa64: "arm64"}.get(machine, hex(machine))
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        sec_table = coff + 20 + opt_size
        for i in range(num_sections):
            off = sec_table + i * 40
            if off + 40 > len(data):
                break
            raw = data[off:off + 8]
            name = raw.rstrip(b"\x00").decode("latin-1", "replace")
            raw_size = struct.unpack_from("<I", data, off + 16)[0]
            raw_off = struct.unpack_from("<I", data, off + 20)[0]
            sections.append((name, raw_off, raw_size))
    except (struct.error, IndexError):
        pass
    return arch, sections


def _parse_elf(data: bytes):
    sections = []
    arch = "unknown"
    try:
        if len(data) < 64:
            return arch, sections
        ei_class = data[4]
        ei_data = data[5]
        endian = "<" if ei_data == 1 else ">"
        is64 = ei_class == 2
        machine = struct.unpack_from(endian + "H", data, 18)[0]
        arch = {0x03: "x86", 0x3e: "x86-64", 0x28: "arm",
                0xb7: "arm64", 0xf3: "riscv"}.get(machine, hex(machine))
        if is64:
            e_shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 0x3a)
        else:
            e_shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 0x2e)
        if e_shoff == 0 or e_shnum == 0:
            return arch, sections
        # locate section header string table
        strtab_off = 0
        if e_shstrndx < e_shnum:
            sh = e_shoff + e_shstrndx * e_shentsize
            if is64:
                strtab_off = struct.unpack_from(endian + "Q", data, sh + 0x18)[0]
            else:
                strtab_off = struct.unpack_from(endian + "I", data, sh + 0x10)[0]
        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            if sh + e_shentsize > len(data):
                break
            name_idx = struct.unpack_from(endian + "I", data, sh)[0]
            if is64:
                offset = struct.unpack_from(endian + "Q", data, sh + 0x18)[0]
                size = struct.unpack_from(endian + "Q", data, sh + 0x20)[0]
            else:
                offset = struct.unpack_from(endian + "I", data, sh + 0x10)[0]
                size = struct.unpack_from(endian + "I", data, sh + 0x14)[0]
            name = ""
            if strtab_off:
                end = data.find(b"\x00", strtab_off + name_idx)
                if end != -1:
                    name = data[strtab_off + name_idx:end].decode("latin-1", "replace")
            sections.append((name, offset, size))
    except (struct.error, IndexError):
        pass
    return arch, sections


def _parse_macho(data: bytes):
    sections = []
    arch = "unknown"
    try:
        magic = data[:4]
        if magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
            is64 = True
        else:
            is64 = False
        endian = "<" if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") else ">"
        cputype = struct.unpack_from(endian + "i", data, 4)[0]
        arch = {7: "x86", 0x01000007: "x86-64", 12: "arm",
                0x0100000c: "arm64"}.get(cputype & 0xffffffff, str(cputype))
        ncmds = struct.unpack_from(endian + "I", data, 16)[0]
        off = 32 if is64 else 28
        for _ in range(ncmds):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(endian + "II", data, off)
            if cmd in (0x1, 0x19):  # LC_SEGMENT / LC_SEGMENT_64
                segname = data[off + 8:off + 24].rstrip(b"\x00").decode("latin-1", "replace")
                if is64:
                    fileoff = struct.unpack_from(endian + "Q", data, off + 0x28)[0]
                    filesize = struct.unpack_from(endian + "Q", data, off + 0x30)[0]
                else:
                    fileoff = struct.unpack_from(endian + "I", data, off + 0x20)[0]
                    filesize = struct.unpack_from(endian + "I", data, off + 0x24)[0]
                sections.append((segname, fileoff, filesize))
            if cmdsize == 0:
                break
            off += cmdsize
    except (struct.error, IndexError):
        pass
    return arch, sections


def section_entropies(data: bytes, fmt: str):
    """Return (arch, [ {name, offset, size, entropy} ])."""
    if fmt == "PE":
        arch, secs = _parse_pe(data)
    elif fmt == "ELF":
        arch, secs = _parse_elf(data)
    elif fmt.startswith("MachO"):
        arch, secs = _parse_macho(data)
    else:
        arch, secs = "unknown", []
    out = []
    for name, off, size in secs:
        if size <= 0 or off <= 0 or off >= len(data):
            out.append({"name": name, "offset": off, "size": size, "entropy": 0.0})
            continue
        chunk = data[off:off + min(size, len(data) - off)]
        out.append({
            "name": name,
            "offset": off,
            "size": size,
            "entropy": shannon_entropy(chunk),
        })
    return arch, out


# ---------------------------------------------------------------------------
# Packer / obfuscation detection
# ---------------------------------------------------------------------------

# Known packer marker section names -> packer label.
_PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".petite": "Petite",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma",
    ".nsp0": "NsPack", ".nsp1": "NsPack",
    ".pelock": "PELock", ".y0da": "yoda",
}

# Raw signature byte sequences -> packer label.
_PACKER_SIGS = [
    (b"UPX!", "UPX"),
    (b"UPX0", "UPX"),
    (b".themida", "Themida"),
    (b"VMProtect", "VMProtect"),
    (b"ASPack", "ASPack"),
    (b"PECompact", "PECompact"),
    (b"MPRESS", "MPRESS"),
    (b"Enigma", "Enigma"),
]


def detect_packers(data: bytes, sections) -> list:
    """Return list of detected packer/obfuscator names."""
    found = set()
    for s in sections:
        key = s["name"].lower().strip()
        if key in _PACKER_SECTIONS:
            found.add(_PACKER_SECTIONS[key])
    # scan first/last 64KB for signatures (cheap + where stubs live)
    head = data[:65536]
    tail = data[-65536:] if len(data) > 65536 else b""
    for sig, label in _PACKER_SIGS:
        if sig in head or (tail and sig in tail):
            found.add(label)
    return sorted(found)


# ---------------------------------------------------------------------------
# Top-level scan
# ---------------------------------------------------------------------------

def fingerprint(data: bytes) -> dict:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "fuzzy": fuzzy_fingerprint(data),
    }


def scan_file(path: str) -> ScanResult:
    if not os.path.exists(path):
        raise FileNotFoundError(f"No such file: {path!r}")
    if not os.path.isfile(path):
        raise ValueError(f"Not a regular file: {path!r}")
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) == 0:
        return ScanResult(
            path=path, size=0, fmt="unknown", arch="unknown",
            sha256=hashlib.sha256(b"").hexdigest(),
            md5=hashlib.md5(b"").hexdigest(),
            fuzzy="0:",
            overall_entropy=0.0,
            sections=[],
            findings=[Finding("EMPTY_FILE", "info", "Empty file",
                              "File has zero bytes; no binary analysis possible.")],
        )

    fmt = detect_format(data)
    fp = fingerprint(data)
    arch, sections = section_entropies(data, fmt)
    overall = shannon_entropy(data)

    result = ScanResult(
        path=path,
        size=len(data),
        fmt=fmt,
        arch=arch,
        sha256=fp["sha256"],
        md5=fp["md5"],
        fuzzy=fp["fuzzy"],
        overall_entropy=overall,
        sections=sections,
    )

    # --- findings ---
    if fmt == "unknown":
        result.findings.append(Finding(
            "FMT_UNKNOWN", "info", "Unrecognized binary format",
            "No PE/ELF/Mach-O magic; entropy/fingerprint still computed."))

    packers = detect_packers(data, sections)
    for p in packers:
        sev = "high" if p in ("Themida", "VMProtect", "Enigma") else "medium"
        result.findings.append(Finding(
            "PACKER", sev, f"Packer/obfuscator detected: {p}",
            f"Marker for {p} found via section name or signature."))

    # high overall entropy with no declared packer = suspicious
    if overall >= 7.2 and not packers and fmt != "unknown":
        result.findings.append(Finding(
            "HIGH_ENTROPY", "medium", "High overall entropy",
            f"Entropy {overall} bits/byte suggests packing/encryption."))

    # per-section anomalies
    for s in sections:
        if s["entropy"] >= 7.4 and s["size"] >= 1024:
            result.findings.append(Finding(
                "SECTION_ENTROPY", "medium",
                f"High-entropy section: {s['name'] or '<unnamed>'}",
                f"entropy={s['entropy']} size={s['size']}; possible packed payload."))
        # executable code sections are normally named; blank/odd names are a flag
        if fmt == "PE" and s["name"] and not s["name"].startswith(".") \
                and s["name"].lower() not in _PACKER_SECTIONS:
            result.findings.append(Finding(
                "ODD_SECTION_NAME", "low",
                f"Non-standard PE section name: {s['name']}",
                "Standard PE sections begin with '.'; custom name may indicate tooling."))

    return result


# ---------------------------------------------------------------------------
# Baseline build + diff
# ---------------------------------------------------------------------------

def build_baseline(paths) -> dict:
    """Build a known-good baseline dict from one or more files.

    Raises:
        ValueError: if *paths* is empty.
    """
    paths = list(paths)
    if not paths:
        raise ValueError("build_baseline requires at least one file path.")
    entries = {}
    for p in paths:
        r = scan_file(p)
        key = os.path.basename(p)
        entries[key] = {
            "sha256": r.sha256,
            "size": r.size,
            "fmt": r.fmt,
            "arch": r.arch,
            "fuzzy": r.fuzzy,
            "overall_entropy": r.overall_entropy,
            "sections": {s["name"]: s["entropy"] for s in r.sections},
        }
    return {"binhunt_baseline": 1, "entries": entries}


def load_baseline(path: str) -> dict:
    """Load and validate a baseline JSON file.

    Raises:
        FileNotFoundError: if *path* does not exist.
        json.JSONDecodeError: if the file is not valid JSON.
        ValueError: if the JSON is valid but is not a binhunt baseline dict.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(
            f"Baseline file {path!r} is not a JSON object; "
            "expected a dict produced by 'binhunt baseline'.")
    if "entries" not in data or not isinstance(data.get("entries"), dict):
        raise ValueError(
            f"Baseline file {path!r} is missing the 'entries' key or it is not "
            "a dict; the file may be corrupt or not a binhunt baseline.")
    return data


def diff_baseline(result: ScanResult, baseline: dict, key: Optional[str] = None) -> list:
    """Compare a scan result against a baseline entry. Returns list[Finding].

    Raises:
        TypeError: if *baseline* is not a dict.
    """
    if not isinstance(baseline, dict):
        raise TypeError(
            f"baseline must be a dict (got {type(baseline).__name__!r}); "
            "use load_baseline() to load from a file.")
    findings = []
    entries = baseline.get("entries", {})
    if key is None:
        key = os.path.basename(result.path)
    base = entries.get(key)
    if base is None:
        findings.append(Finding(
            "NO_BASELINE", "high", "No baseline entry for this binary",
            f"'{key}' is not in the baseline; cannot prove integrity."))
        return findings

    if base.get("sha256") == result.sha256:
        findings.append(Finding(
            "MATCH", "info", "Hash matches baseline",
            "sha256 identical to known-good; binary is unmodified."))
        return findings

    # hashes differ -> tampering. Quantify how different.
    sim = fuzzy_similarity(base.get("fuzzy", ""), result.fuzzy)
    findings.append(Finding(
        "HASH_MISMATCH", "critical", "Binary differs from baseline",
        f"sha256 mismatch (baseline={base.get('sha256','?')[:16]}..., "
        f"got={result.sha256[:16]}...). Fuzzy similarity={sim:.0%}."))

    if base.get("size") != result.size:
        findings.append(Finding(
            "SIZE_CHANGE", "high", "File size changed",
            f"baseline={base.get('size')} bytes, now={result.size} bytes "
            f"(delta={result.size - base.get('size', 0):+d})."))

    # section entropy drift (e.g. code section newly packed/patched)
    base_secs = base.get("sections", {})
    now_secs = {s["name"]: s["entropy"] for s in result.sections}
    for name, ent in now_secs.items():
        if name in base_secs:
            delta = ent - base_secs[name]
            if abs(delta) >= 0.5:
                findings.append(Finding(
                    "SECTION_DRIFT", "high",
                    f"Section '{name or '<unnamed>'}' entropy changed",
                    f"baseline={base_secs[name]} now={ent} (delta={delta:+.3f}); "
                    "possible code patch or injected payload."))
        else:
            findings.append(Finding(
                "SECTION_ADDED", "high", f"New section '{name or '<unnamed>'}'",
                "Section not present in baseline; possible injected segment."))
    for name in base_secs:
        if name not in now_secs:
            findings.append(Finding(
                "SECTION_REMOVED", "medium", f"Section '{name or '<unnamed>'}' missing",
                "Baseline section absent in current binary."))
    return findings
