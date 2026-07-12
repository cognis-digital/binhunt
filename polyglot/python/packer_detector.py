"""polyglot/python/packer_detector.py - Binary packer/obfuscator detector.

Complete, self-contained module for detecting common PE packers and obfuscators
by analyzing headers, sections, entropy, and known signatures.
"""

import os
import struct
import math
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any


# =============================================================================
# CONSTANTS - Known Packer Signatures
# =============================================================================

PACKER_SIGNATURES: Dict[str, bytes] = {
    # UPX variants
    "UPX1": b"\x92\x87\x0p",
    "UPX2": b"UPX!",
    "UPX3": b"UPX   ",
    "UPX4": b"UPX   ",
    "UPX5": b"UPX   ",
    # Themida/ThemProtect
    "Themida": b"\x01\x02\x03\x04",  # Magic for Themida PE
    "ThemProtect": b"\xDE\xAD\xBE\xEF",
    # ASPack variants
    "ASPack": b"ASPack",
    "ASPack2": b"ASPack",
    # PECompact
    "PECompact": b"PCCmp",
    # Themida 4.0+
    "Themida4": b"\x1E\x3C\x5A\x6D",
    # ThemProtect 2.0+
    "ThemProtect2": b"TPROTECT",
    # ASPack 2.0+
    "ASPack2_0": b"ASPack2.0",
    # PECompact 3.0+
    "PECompact3": b"PCCmp3.0",
    # Themida 5.0+
    "Themida5": b"\x1E\x3C\x5A\x6D",
    # ThemProtect 2.0+
    "ThemProtect2_0": b"TPROTECT",
    # ASPack 2.0+
    "ASPack2_0": b"ASPack2.0",
    # PECompact 3.0+
    "PECompact3": b"PCCmp3.0",
}

# Known section names indicating packing
PACKER_SECTION_NAMES: List[str] = [
    ".upx", ".upx1", ".upx2", ".upx3", ".upx4", ".upx5",
    ".themida", ".themprotect", ".pecompact", ".pccmp",
    ".packed", ".packer", ".obf", ".obfuscate",
]

# Known import patterns for packers (PE files)
PACKER_IMPORTS: List[str] = [
    "kernel32.dll!SetWindowsHookExW",  # Themida hooking pattern
    "ntdll.dll!NtQuerySystemInformation",  # Common in packed binaries
    "user32.dll!GetAsyncKeyState",  # Keyloggers/packers
    "gdi32.dll!GdiSetWindowsTextEx",  # Themida pattern
]

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def read_bytes_at(path: Path, offset: int, size: int) -> bytes:
    """Safely read bytes from file at given offset."""
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            return f.read(size)
    except (IOError, OSError):
        return b""

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence. Higher = more random."""
    if not data:
        return 0.0
    
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    
    return entropy

def calculate_section_entropy(path: Path, pe_data: bytes) -> Dict[str, float]:
    """Calculate entropy per section from PE header data."""
    sections = []
    offset = 64  # Start of Section Table
    
    num_sections = struct.unpack_from("I", pe_data, offset)[0]
    
    for _ in range(num_sections):
        name_offset = offset + 8 * _
        name_len = min(80, len(pe_data) - name_offset)
        name = pe_data[name_offset:name_offset+name_len].rstrip(b"\x00")
        
        if name:
            sections.append((name.decode("ascii", errors="replace"), offset))
    
    return {name: calculate_entropy(data) for name, data in 
            [(name, read_bytes_at(path, offset + 8 * i, 64)) 
             for i, (name, _) in enumerate(sections[:10])]}

# =============================================================================
# HEADER PARSERS
# =============================================================================

def parse_pe_header(path: Path) -> Optional[Dict[str, Any]]:
    """Parse PE header and return structured data."""
    pe_data = read_bytes_at(path, 0, 64)
    
    if len(pe_data) < 64:
        return None
    
    magic = struct.unpack("<H", pe_data[:2])[0]
    
    if magic == 0x010b:  # PE32
        machine = struct.unpack("<H", pe_data[4:6])[0]
        num_sections = struct.unpack("<I", pe_data[60:64])[0]
        return {
            "format": "PE32",
            "machine": machine,
            "num_sections": num_sections,
            "is_pe": True
        }
    elif magic == 0x020b:  # PE32+
        machine = struct.unpack("<H", pe_data[4:6])[0]
        num_sections = struct.unpack("<I", pe_data(68))[0]
        return {
            "format": "PE32+",
            "machine": machine,
            "num_sections": num_sections,
            "is_pe": True
        }
    
    return None

def parse_elf_header(path: Path) -> Optional[Dict[str, Any]]:
    """Parse ELF header and return structured data."""
    elf_data = read_bytes_at(path, 0, 64)
    
    if len(elf_data) < 64:
        return None
    
    e_ident = elf_data[:16]
    ei_class = e_ident[4]
    ei_data = e_ident[5]
    ei_machine = struct.unpack("<H", e_ident[18:20])[0]
    
    if ei_class == 2 and ei_data == 1:  # 64-bit, little-endian
        return {
            "format": "ELF64",
            "class": "64-bit",
            "endianness": "little",
            "machine": ei_machine,
            "is_elf": True
        }
    elif ei_class == 1 and ei_data == 1:  # 32-bit, little-endian
        return {
            "format": "ELF32",
            "class": "32-bit",
            "endianness": "little",
            "machine": ei_machine,
            "is_elf": True
        }
    
    return None

# =============================================================================
# PACKER DETECTION LOGIC
# =============================================================================

def detect_packer_signatures(path: Path) -> List[Dict[str, Any]]:
    """Detect known packer signatures in binary."""
    pe_data = read_bytes_at(path, 0, 64)
    
    found = []
    
    for name, sig in PACKER_SIGNATURES.items():
        if sig and sig in pe_data[:256]:
            found.append({
                "name": name,
                "type": "signature",
                "offset": pe_data.find(sig),
                "confidence": 0.95
            })
    
    return found

def detect_section_heuristics(path: Path, header_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detect packer indicators from section names and entropy."""
    found = []
    
    # Check section names
    pe_data = read_bytes_at(path, 0, 64)
    num_sections = header_info.get("num_sections", 0) if "num_sections" in header_info else 1
    
    for i in range(min(num_sections, 20)):
        name_offset = 64 + 8 * i
        name_len = min(80, len(pe_data) - name_offset)
        name = pe_data[name_offset:name_offset+name_len].rstrip(b"\x00")
        
        if name:
            section_name = name.decode("ascii", errors="replace").lower()
            
            # Check for packer-related names
            for packer_name in PACKER_SECTION_NAMES:
                if packer_name.lower() in section_name:
                    found.append({
                        "name": "section_heuristic",
                        "type": "packer_section",
                        "offset": name_offset,
                        "confidence": 0.85,
                        "details": f"Section named '{section_name}' suggests packing"
                    })
                    break
            
            # Check for high entropy (potential packed data)
            section_data = read_bytes_at(path, 64 + 8 * i, 64)
            if len(section_data) >= 32:
                entropy = calculate_entropy(section_data[:1024])
                if entropy > 7.5 and "packed" not in section_name.lower():
                    found.append({
                        "name": "entropy_anomaly",
                        "type": "high_entropy_section",
                        "offset": name_offset,
                        "confidence": min(0.9, (entropy - 7.5) / 2),
                        "details": f"High entropy ({entropy:.3f}) in section '{section_name}'"
                    })
    
    return found

def detect_import_patterns(path: Path) -> List[Dict[str, Any]]:
    """Detect suspicious import patterns common to packers."""
    found = []
    
    # Try to parse imports (simplified - would need proper parsing for full accuracy)
    pe_data = read_bytes_at(path, 0, 64)
    num_sections = pe_data[60:64].unpack("<I")[0] if len(pe_data) >= 64 else 1
    
    # Check for common packer import patterns in first few sections
    suspicious_imports = []
    
    for i in range(min(num_sections, 5)):
        name_offset = 64 + 8 * i
        name_len = min(80, len(pe_data) - name_offset)
        name = pe_data[name_offset:name_offset+name_len].rstrip(b"\x00")
        
        if name:
            section_name = name.decode("ascii", errors="replace").lower()
            
            # Check for packer-related imports in this section's data range
            data_start = 64 + 8 * i + 40
            data_end = min(data_start + 1024, len(pe_data))
            data = pe_data[data_start:data_end] if data_start < len(pe_data) else b""
            
            for pattern in PACKER_IMPORTS:
                if pattern.encode() in data:
                    suspicious_imports.append({
                        "pattern": pattern,
                        "section_offset": name_offset,
                        "confidence": 0.8
                    })
    
    if suspicious_imports:
        found.append({
            "name": "import_pattern",
            "type": "suspicious_imports",
            "offset": 64,
            "confidence": 0.75,
            "details": f"Found {len(suspicious_imports)} suspicious import patterns"
        })
    
    return found

def detect_entropy_anomalies(path: Path) -> List[Dict[str, Any]]:
    """Detect overall entropy anomalies that suggest packing."""
    found = []
    
    # Read entire file for rough entropy check (sampled to avoid memory issues)
    try:
        with open(path, "rb") as f:
            data = f.read(1024 * 1024)  # First 1MB
            
            if len(data) < 1024:
                return found
        
            overall_entropy = calculate_entropy(data)
            
            # Very high entropy can indicate packing or encryption
            if overall_entropy > 7.8:
                found.append({
                    "name": "overall_entropy",
                    "type": "high_overall_entropy",
                    "offset": 0,
                    "confidence": min(0.95, (overall_entropy - 7.8) / 2),
                    "details": f"Overall entropy: {overall_entropy:.3f} (suspiciously high)"
                })
    except IOError:
        pass
    
    return found

# =============================================================================
# MAIN DETECTOR CLASS
# =============================================================================

class PackerDetector:
    """Main detector class for binary packer analysis."""
    
    def __init__(self, path: Path):
        self.path = path
        self.header_info: Dict[str, Any] = {}
        self.results: List[Dict[str, Any]] = []
        
    def analyze(self) -> Dict[str, Any]:
        """Run full analysis and return results."""
        # Parse headers
        pe_header = parse_pe_header(self.path)
        elf_header = parse_elf_header(self.path)
        
        if pe_header:
            self.header_info["pe"] = pe_header
        
        if elf_header:
            self.header_info["elf"] = elf_header
        
        # Run all detectors
        self.results.extend(detect_packer_signatures(self.path))
        self.results.extend(detect_section_heuristics(self.path, self.header_info))
        self.results.extend(detect_import_patterns(self.path))
        self.results.extend(detect_entropy_anomalies(self.path))
        
        # Calculate overall score
        total_confidence = sum(r.get("confidence", 0) for r in self.results)
        max_confidence = len(self.results) if self.results else 1
        
        avg_confidence = total_confidence / max_confidence if max_confidence > 0 else 0
        
        # Determine primary packer type
        primary_packer = self._determine_primary_packer()
        
        return {
            "path": str(self.path),
            "format": pe_header.get("format") or elf_header.get("format") if pe_header or elf_header else "unknown",
            "primary_packer": primary_packer,
            "confidence_score": round(avg_confidence * 100, 2),
            "findings_count": len(self.results),
            "details": self.results
        }
    
    def _determine_primary_packer(self) -> Optional[str]:
        """Determine the most likely primary packer."""
        if not self.results:
            return None
        
        # Group by type and find highest confidence
        grouped = {}
        for result in self.results:
            rtype = result.get("type", "unknown")
            if rtype not in grouped:
                grouped[rtype] = []
            grouped[rtype].append(result)
        
        best_type = None
        best_score = 0
        
        for rtype, items in grouped.items():
            # Score based on confidence and number of hits
            avg_conf = sum(i.get("confidence", 0) for i in items) / len(items)
            score = avg_conf * len(items)
            
            if score > best_score:
                best_score = score
                best_type = rtype
        
        # Map type to human-readable name
        type_map = {
            "signature": "Known signature match",
            "packer_section": "Packer-related section detected",
            "suspicious_imports": "Suspicious import patterns found",
            "high_entropy_section": "High-entropy section (possible packed data)",
            "high_overall_entropy": "Overall high entropy"
        }
        
        return type_map.get(best_type, best_type) if best_type else None
    
    def get_summary(self) -> str:
        """Get human-readable summary."""
        primary = self._determine_primary_packer() or "Unknown/None detected"
        confidence = self.results[0].get("confidence", 0) * 100 if self.results else 0
        
        lines = [
            f"Packer Analysis: {self.path}",
            f"Format: {self.header_info.get('pe', {}).get('format') or 
                   self.header_info.get('elf', {}).get('format') or 'Unknown'}",
            f"Primary Packer: {primary}",
            f"Confidence Score: {confidence:.1f}%",
            f"Total Findings: {len(self.results)}",
        ]
        
        if self.results:
            lines.append("\nDetailed Findings:")
            for i, r in enumerate(self.results[:5], 1):  # Limit to first 5
                name = r.get("name", "Unknown")
                ctype = r.get("type", "unknown")
                conf = r.get("confidence", 0) * 100
                offset = hex(r.get("offset", 0))
                
                lines.append(f"  {i}. [{ctype}] {name