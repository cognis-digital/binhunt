"""
polyglot/python/obfuscator_finder.py

Game/desktop binary integrity scanner - obfuscator detection module.
Fingerprints executables and detects common packers/obfuscators.
"""

import os
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, BinaryIO


class ObfuscatorType(Enum):
    """Known obfuscator/packer types."""
    UNKNOWN = 0
    UPX = 1
    PECompact = 2
    THEMIDA = 3
    VMProtect = 4
    ENIGMA = 5
    ASPACK = 6
    ARACHNID = 7
    GENERIC_PACKER = 8


@dataclass
class ObfuscatorResult:
    """Single obfuscation detection result."""
    type: ObfuscatorType
    confidence: float  # 0.0 to 1.0
    evidence: List[str] = field(default_factory=list)
    offset: int = 0
    
    def __str__(self):
        conf_str = f"{int(self.confidence * 100)}%" if self.confidence > 0 else "unknown"
        return f"{self.type.name}: {conf_str}"


class ObfuscatorFinder:
    """
    Detects obfuscators and packers in binary executables.
    
    Uses multiple strategies:
    - Magic byte/signature matching
    - String pattern search
    - Section analysis
    - Import table inspection
    - Entropy heuristics
    """
    
    # Known UPX signatures (various versions)
    UPX_SIGNATURES = [
        b'UPX!',                    # Classic UPX 1.x/2.x
        b'\x50\x55\x58\x21',       # ASCII "UPX!" as bytes
        b'\x4D\x5A',                # PE header (UPX often wraps PE)
    ]
    
    # PECompact signatures
    PECOMPACT_SIGNATURES = [
        b'PECompact',               # Classic PECompact
        b'PECompact2',              # PECompact 2.x
        b'\x50\x45\x43\x6F\x6D\x70\x61\x63\x74',  # "PECompact" ASCII
    ]
    
    # Common packer strings found in data sections
    PACKER_STRINGS = [
        b'UPX', b'upx', b'UPX!', b'\x50\x55\x58\x21',
        b'PECompact', b'PECompact2', b'PEC2',
        b'Themida', b'themida', b'THMIDA',
        b'VMProtect', b'vmprotect', b'VMPROTECT',
        b'Enigma', b'enigma', b'ENIGMA',
        b'ASPack', b'aspack', b'ASP',
        b'Arachnid', b'arachnid',
        b'Thaumiel', b'thaumiel',
        b'VirusProtect', b'virusprotect',
        b'Morpho', b'morpho',
        b'PackMyPete', b'packmypete',
    ]
    
    # Anti-debugging strings (often present in packed binaries)
    ANTI_DEBUG_STRINGS = [
        b'IsDebuggerPresent', b'GetTickCount', b'Sleep',
        b'ReadProcessMemory', b'WriteProcessMemory',
        b'NtQueryInformationProcess', b'CreateToolhelp32Snapshot',
        b'EnumProcesses', b'IsWow64Process',
    ]
    
    # Known UPX header patterns (little-endian)
    UPX_HEADER_PATTERNS = [
        (b'\x50\x55\x58\x21', 0, "UPX!"),      # ASCII
        (b'\x4D\x5A', 0, "PE Header"),          # PE header start
    ]
    
    def __init__(self):
        self.results: List[ObfuscatorResult] = []
        self.file_path: Optional[str] = None
    
    def find_obfuscators(self, file_path: str) -> List[ObfuscatorResult]:
        """
        Main entry point for obfuscator detection.
        
        Args:
            file_path: Path to the binary file
            
        Returns:
            List of detected obfuscation results
        """
        self.file_path = file_path
        self.results = []
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            # Run all detection strategies in parallel-ish order
            self._check_magic_bytes(f, file_size)
            self._check_strings(f, file_size)
            self._check_section_layout(f, file_size)
            self._check_imports(f, file_size)
            self._check_entropy(f, file_size)
            self._check_anti_debug(f, file_size)
        
        # Merge and deduplicate results
        return self._merge_results()
    
    def _check_magic_bytes(self, f: BinaryIO, size: int) -> None:
        """Check for known magic byte signatures."""
        header = f.read(64)  # Read enough to catch most headers
        
        # UPX detection
        if b'UPX!' in header or header[:4] == b'\x50\x55\x58\x21':
            self.results.append(ObfuscatorResult(
                type=ObfuscatorType.UPX,
                confidence=0.95,
                evidence=[f"Found UPX magic at offset 0"],
                offset=0
            ))
        
        # PECompact detection
        if b'PECompact' in header or b'PEC2' in header:
            self.results.append(ObfuscatorResult(
                type=ObfuscatorType.PECOMPACT,
                confidence=0.95,
                evidence=[f"Found PECompact signature"],
                offset=header.find(b'PECompact') if b'PECompact' in header else 0
            ))
    
    def _check_strings(self, f: BinaryIO, size: int) -> None:
        """Search for known packer strings throughout the file."""
        # Read entire file (reasonable for executables < 1GB)
        data = f.read()
        
        found_offsets = {}
        for pattern in self.PACKER_STRINGS:
            if pattern.isascii():
                offset = data.find(pattern)
                if offset >= 0 and offset not in found_offsets:
                    found_offsets[offset] = pattern.decode('ascii', errors='ignore')
            
            # Also check as bytes
            elif len(pattern) > 0:
                offset = data.find(pattern)
                if offset >= 0 and offset not in found_offsets:
                    found_offsets[offset] = pattern.hex()
        
        if found_offsets:
            max_confidence = min(1.0, len(found_offsets) * 0.15)
            self.results.append(ObfuscatorResult(
                type=ObfuscatorType.GENERIC_PACKER,
                confidence=max_confidence,
                evidence=list(found_offsets.keys())[:5],  # Limit to first 5 offsets
                offset=min(found_offsets.values()) if found_offsets else 0
            ))
    
    def _check_section_layout(self, f: BinaryIO, size: int) -> None:
        """Analyze PE section layout for packing artifacts."""
        header = f.read(64)
        
        # Check if it's a PE file
        if len(header) >= 2 and header[:2] == b'\x4D\x5A':
            pe_offset = 0
            
            # Parse PE header
            try:
                pe_magic, = struct.unpack('<H', header[60:62])
                
                if pe_magic == 0x10b:  # PE32 (little-endian)
                    num_sections, = struct.unpack('<I', header[64:68])
                    
                    # UPX often creates a specific section layout
                    if num_sections > 0 and num_sections < 10:
                        # Check for .UPX or similar sections
                        pe_offset = 64
                        
                        # Read Optional Header to find section table
                        optional_header_size, = struct.unpack('<H', header[28:30])
                        
                        if optional_header_size > 0:
                            opt_start = 100  # PE header + optional header size
                            
                            # Check for UPX-specific fields in Optional Header
                            if optional_header_size >= 56:
                                # UPX often sets specific flags
                                characteristics, = struct.unpack('<I', header[28:32])
                                
                                # UPX typically has these characteristics set
                                upx_flags = (0x1000 | 0x4000)  # IMAGE_DLLCHARACTERISTICS_DONT_RESOLVE_FORWARDERS | DONT_FORCED_IMAGE_BASE
                                
                                if characteristics & upx_flags:
                                    self.results.append(ObfuscatorResult(
                                        type=ObfuscatorType.UPX,
                                        confidence=0.75,
                                        evidence=["UPX-like section flags detected"],
                                        offset=pe_offset
                                    ))
            except (struct.error, IndexError):
                pass
    
    def _check_imports(self, f: BinaryIO, size: int) -> None:
        """Inspect import table for packing library imports."""
        header = f.read(64)
        
        if len(header) < 2 or header[:2] != b'\x4D\x5A':
            return
        
        pe_offset = 0
        try:
            pe_magic, = struct.unpack('<H', header[60:62])
            
            if pe_magic == 0x10b:  # PE32
                optional_header_size, = struct.unpack('<H', header[28:30])
                
                if optional_header_size > 0 and optional_header_size >= 56:
                    opt_start = 100
                    
                    # Check for UPX import directory
                    data_directory_offset, = struct.unpack('<I', header[40:44])
                    
                    if data_directory_offset > 0:
                        data_dir_rva, = struct.unpack('<I', header[opt_start + 24:opt_start + 28])
                        
                        # UPX often imports from specific libraries
                        upx_imports = [b'upx', b'UPX', b'libupx']
                        
                        for imp in upx_imports:
                            if imp.lower() in header[100:].lower():
                                self.results.append(ObfuscatorResult(
                                    type=ObfuscatorType.UPX,
                                    confidence=0.85,
                                    evidence=[f"UPX import reference found"],
                                    offset=header.find(imp) if imp.isascii() else 100
                                ))
        except (struct.error, IndexError):
            pass
    
    def _check_entropy(self, f: BinaryIO, size: int) -> None:
        """Check entropy of sections - high entropy suggests packing."""
        header = f.read(64)
        
        if len(header) < 2 or header[:2] != b'\x4D\x5A':
            return
        
        pe_offset = 0
        try:
            pe_magic, = struct.unpack('<H', header[60:62])
            
            if pe_magic == 0x10b:  # PE32
                optional_header_size, = struct.unpack('<H', header[28:30])
                
                if optional_header_size > 0 and optional_header_size >= 56:
                    opt_start = 100
                    
                    # Read section headers
                    data_directory_offset, = struct.unpack('<I', header[40:44])
                    
                    if data_directory_offset > 0:
                        data_dir_rva, = struct.unpack('<I', header[opt_start + 24:opt_start + 28])
                        
                        # Calculate section table RVA (simplified)
                        section_table_rva = opt_start + 56
                        
                        # Read sections and check entropy
                        num_sections, = struct.unpack('<I', header[64:68])
                        
                        if num_sections > 0:
                            # Check first few sections for high entropy
                            for i in range(min(num_sections, 3)):
                                section_offset = opt_start + 56 + (i * 40)
                                
                                try:
                                    name_len, = struct.unpack('<H', header[section_offset:section_offset+2])
                                    
                                    # Read section data if possible
                                    if section_offset + 2 < len(header):
                                        # Check for high-entropy patterns
                                        chunk_size = min(1024, len(header) - section_offset - 2)
                                        
                                        # Simple entropy check (normalized to 0-1)
                                        chunk = header[section_offset+2:section_offset+2+chunk_size]
                                        if chunk:
                                            unique_ratio = len(set(chunk)) / min(256, len(chunk))
                                            
                                            if unique_ratio > 0.85 and i == 0:
                                                self.results.append(ObfuscatorResult(
                                                    type=ObfuscatorType.GENERIC_PACKER,
                                                    confidence=0.6,
                                                    evidence=["High entropy in first section"],
                                                    offset=section_offset
                                                ))
                                except (struct.error, IndexError):
                                    pass
        except (struct.error, IndexError):
            pass
    
    def _check_anti_debug(self, f: BinaryIO, size: int) -> None:
        """Check for anti-debugging strings common in packed binaries."""
        data = f.read()
        
        found_count = 0
        evidence = []
        
        for pattern in self.ANTI_DEBUG_STRINGS:
            if len(pattern) > 0 and pattern.isascii():
                offset = data.find(pattern)
                if offset >= 0:
                    found_count += 1
                    evidence.append(f"Found '{pattern.decode()}' at {offset}")
        
        # Anti-debugging + other signs suggests packing
        if found_count >= 2:
            self.results.append(ObfuscatorResult(
                type=ObfuscatorType.GENERIC_PACKER,
                confidence=min(0.9, 0.3 + (found_count * 0.1)),
                evidence=evidence[:5],
                offset=data.find(self.ANTI_DEBUG_STRINGS[0]) if self.ANTI_DEBUG_STRINGS else 0
            ))
    
    def _merge_results(self) -> List[ObfuscatorResult]:
        """Merge and deduplicate detection results."""
        merged = []
        
        # Sort by confidence (highest first)
        sorted_results = sorted(self.results, key=lambda r: r.confidence, reverse=True)
        
        for result in sorted_results:
            # Skip if already have a high-confidence match of same type
            existing_same_type = [r for r in merged 
                                  if r.type == result.type and r.confidence >= 0.8]
            
            if not existing_same_type:
                merged.append(result)
        
        return merged
    
    def get_summary(self) -> str:
        """Get a human-readable summary of findings."""
        if not self.results:
            return "No obfuscation detected."
        
        lines = []
        for result in self.results[:5]:  # Limit to top 5
            conf_pct = f"{int(result.confidence * 100)}%" if result.confidence > 0 else "?"
            lines.append(f"  - {result.type.name}: {conf_pct}")
        
        return "\n".join(lines)


def main():
    """Demo/entry point for testing the obfuscator finder."""
    import sys
    
    # Default test file (will use provided args or find a sample)
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        # Try to find a common executable in current directory
        for candidate in ['python', 'python3', 'ls', 'cat']:
            path = os.path.join(os.getcwd(), candidate)
            if os.path.isfile(path):
                target = path
                break
        else:
            print("Usage: python obfuscator_finder.py <binary_file>")
            print("\nNo file specified, showing class info...")
            print(f"  Known packers: {len(ObfuscatorFinder.PACKER_STRINGS)} string patterns")
            print(f"  Anti-debug strings: {len(ObfuscatorFinder.ANTI_DEBUG_STRINGS)} patterns")
            return
    
    if not os.path.exists(target):
        print(f"Error: File not found: {target}")
        sys.exit(1)
    
    finder =