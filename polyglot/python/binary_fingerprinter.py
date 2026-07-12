"""
polyglot/python/binary_fingerprinter.py

A complete binary fingerprinter for the 'binhunt' tool.
Fingerprints executables, detects packers/obfuscators, and diffs against baselines.

Usage:
    from polyglot.python.binary_fingerprinter import BinaryFingerprinter
    
    scanner = BinaryFingerprinter()
    result = scanner.scan("/path/to/binary.exe")
    print(result)
"""

import os
import struct
import hashlib
import re
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass


@dataclass
class FingerprintResult:
    """Structured result from a binary scan."""
    path: str
    size: int
    magic: str
    is_pe: bool = False
    section_count: int = 0
    entropy: float = 0.0
    sha256: str = ""
    md5: str = ""
    packer_detected: List[str] = None
    suspicious_strings: List[str] = None
    import_table_hash: str = ""
    raw_header_hash: str = ""


class BinaryFingerprinter:
    """
    A robust binary fingerprinter for PE/ELF/Mach-O executables.
    
    Detects:
    - File type via magic numbers
    - Packer signatures (UPX, Themida, etc.)
    - High entropy regions indicating compression
    - Suspicious strings (URLs, packer markers)
    """

    # Known PE magic and structure
    PE_MAGIC = b'MZ'
    
    # Common packer signatures (case-insensitive byte patterns)
    PACKER_SIGNATURES: Dict[str, bytes] = {
        'UPX': b'\x52\x41\x58',  # UPX header "RAX"
        'Themida': b'Themida',
        'VMProtect': b'Vertical Mach',
        'Pafy': b'PAFY',
        'ASPack': b'ASPack',
        'PECompact2': b'\x50\x45\x43\x32',  # PECompact2 "PC2"
        'Themida2': b'THMDIA',
    }

    # Common obfuscator markers
    OBFUSCATOR_MARKERS: List[bytes] = [
        b'VMProtect',
        b'Digital Protections',
        b'Stellar Protection',
        b'\x4D\x50\x32',  # MP2 (MPRESS)
        b'\x41\x58\x32',  # AX2
    ]

    def __init__(self, entropy_threshold: float = 7.5):
        """
        Initialize the scanner.
        
        Args:
            entropy_threshold: Entropy above this indicates possible packing (0-8)
        """
        self.entropy_threshold = entropy_threshold
    
    def scan(self, path: str, deep: bool = True) -> FingerprintResult:
        """
        Perform a complete fingerprint analysis on the binary.
        
        Args:
            path: Path to the executable file
            deep: If True, perform full analysis including string extraction
            
        Returns:
            A FingerprintResult object with all findings
        """
        if not os.path.isfile(path):
            raise FileNotFoundError(f"File not found: {path}")
        
        result = self._basic_scan(path)
        
        if deep and result.is_pe:
            result = self._deep_pe_analysis(result, path)
        
        return result
    
    def _basic_scan(self, path: str) -> FingerprintResult:
        """Perform quick fingerprinting on any file type."""
        with open(path, 'rb') as f:
            data = f.read()
        
        size = len(data)
        magic = self._detect_magic(data[:16])
        
        # Calculate SHA-256 and MD5 for baseline comparison
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        
        # Quick entropy check on first 8KB (fast, representative)
        sample = data[:8192] if size > 8192 else data
        result_entropy = self._calculate_entropy(sample)
        
        is_pe = magic == 'PE' or magic.startswith('MZ')
        section_count = 0
        
        # Quick PE header check for section count
        if is_pe and len(data) >= 64:
            try:
                pe_offset = struct.unpack('<I', data[60:64])[0]
                if pe_offset < len(data):
                    num_sections = struct.unpack('<H', data[pe_offset:pe_offset+2])[0]
                    section_count = num_sections
            except (struct.error, IndexError):
                pass
        
        # Check for packers in the header region
        header_region = data[:64] if is_pe else data[:16384]
        packer_detected = self._check_packer_signatures(header_region)
        
        return FingerprintResult(
            path=path,
            size=size,
            magic=magic,
            is_pe=is_pe,
            section_count=section_count,
            entropy=result_entropy,
            sha256=sha256,
            md5=md5,
            packer_detected=packer_detected or [],
        )
    
    def _deep_pe_analysis(self, result: FingerprintResult, path: str) -> FingerprintResult:
        """Perform deep PE-specific analysis."""
        
        # Extract and hash the raw header (first 64 bytes of PE are stable)
        with open(path, 'rb') as f:
            header = f.read(64)
        result.raw_header_hash = hashlib.sha256(header).hexdigest()
        
        # Extract import table hashes if available
        try:
            from pefile import PE
            pe = PE(path)
            
            # Hash the combined imports (sorted for consistency)
            import_names = []
            for imp in pe.DIRECTORY_ENTRY_IMPORT:
                name = imp.name.decode('utf-8', errors='ignore') if imp.name else ''
                import_names.append(name.lower())
            
            result.import_table_hash = hashlib.sha256(
                b'\x00'.join(n.encode() for n in sorted(import_names))
            ).hexdigest()
            
            # Check for suspicious imports (common packer hooks)
            suspicious_imports = [
                'kernel32.dll:LoadLibraryA',
                'kernel32.dll:GetModuleHandleA',
                'ntdll.dll:NtQueryInformationProcess',
                'user32.dll:SetWindowsHookExA',
            ]
            
            for sus in suspicious_imports:
                if sus.encode() in header or sus.encode() in data[:4096]:
                    result.packer_detected.append(sus)
                    
        except ImportError:
            # pefile not available, use manual parsing
            result.import_table_hash = hashlib.sha256(header).hexdigest()
        
        # Extract and analyze strings (packer signatures often hide in strings)
        if result.is_pe:
            result.suspicious_strings = self._extract_pe_strings(path)[:100]
            
            # Check for packer markers in extracted strings
            string_markers = [b'UPX', b'Themida', b'VMProtect', b'ASPack']
            for marker in string_markers:
                if marker.lower() in result.suspicious_strings:
                    result.packer_detected.append(marker.decode())
        
        return result
    
    def _detect_magic(self, data: bytes) -> str:
        """Detect file type from magic numbers."""
        # Common magic signatures
        magics = {
            b'MZ': 'PE (DOS/Windows)',
            b'\x7fELF': 'ELF',
            b'CFAR\x00\x00\x00\x00': 'Mach-O (Fat)',
            b'\xca\xfe\xba\xbe': 'Mach-O (64-bit)',
            b'\xce\xfa\xed\xfe': 'Mach-O (32-bit)',
        }
        
        for magic, name in magics.items():
            if data.startswith(magic):
                return name
        
        # Fallback: check first 16 bytes as hex
        hex_start = data[:16].hex()
        return f'Unknown ({hex_start})'
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of the given data."""
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        
        length = len(data)
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * (p + 1e-30).bit_length()
        
        return entropy
    
    def _check_packer_signatures(self, data: bytes) -> List[str]:
        """Check for known packer signatures in the header region."""
        detected = []
        
        for name, pattern in self.PACKER_SIGNATURES.items():
            if pattern.lower() in data[:4096].lower():
                detected.append(name)
        
        return detected
    
    def _extract_pe_strings(self, path: str, max_count: int = 100) -> List[str]:
        """Extract printable strings from a PE file."""
        try:
            from pefile import PE
            pe = PE(path)
            
            # Extract from sections (text/data segments)
            strings = []
            for section in pe.sections:
                if not section.Name or b'.data' in section.Name.lower():
                    continue
                
                # Get raw data, handling optional header offset
                try:
                    vaddr = struct.unpack('<I', section.PointerToRawData)[0]
                    size = section.Misc.VirtualSize
                    
                    # Read from file at the right offset
                    if vaddr < len(pe.data):
                        start_offset = pe.OPTIONAL_HEADER.Machine - 256
                        raw_data = pe.data[vaddr:][:size]
                        
                        # Extract printable strings (min length 4)
                        current = b''
                        for byte in raw_data:
                            if 32 <= byte < 127 or byte == 0x20:
                                current += bytes([byte])
                            else:
                                if len(current) >= 4:
                                    strings.append(current.decode('utf-8', errors='ignore'))
                                current = b''
                        
                        # Check remaining
                        if len(current) >= 4:
                            strings.append(current.decode('utf-8', errors='ignore'))
                except (struct.error, IndexError):
                    continue
            
            return strings[:max_count]
            
        except ImportError:
            # Fallback: simple string extraction from file
            with open(path, 'rb') as f:
                data = f.read()
            
            current = b''
            strings = []
            for byte in data:
                if 32 <= byte < 127 or byte == 0x20:
                    current += bytes([byte])
                else:
                    if len(current) >= 4:
                        try:
                            s = current.decode('utf-8')
                            if any(c.isalpha() for c in s):  # Filter mostly alphanumeric
                                strings.append(s)
                        except UnicodeDecodeError:
                            pass
                    current = b''
            
            return strings[:max_count]
    
    def diff_against_baseline(self, binary_path: str, baseline_hash: str) -> Dict[str, Any]:
        """
        Compare a binary against a known-good baseline hash.
        
        Returns a dict indicating if the binary matches or has been modified.
        """
        result = self.scan(binary_path)
        
        return {
            'matches_baseline': result.sha256 == baseline_hash,
            'current_sha256': result.sha256,
            'baseline_sha256': baseline_hash,
            'modified_bytes_estimate': 0 if result.matches_baseline else self._estimate_changes(binary_path),
        }
    
    def _estimate_changes(self, path: str) -> int:
        """Estimate how many bytes might have changed (rough heuristic)."""
        with open(path, 'rb') as f:
            data = f.read()
        
        # Compare against common baseline patterns for this file type
        if data[:2] == b'MZ':  # PE file
            # Check header stability
            stable_header = data[64:]  # Skip DOS header and PE signature
            return len(stable_header) - len(set(stable_header)) // 10  # Rough estimate
        
        return 0
    
    def get_summary(self, result: FingerprintResult) -> str:
        """Get a human-readable summary of the scan results."""
        lines = [f"Binary: {result.path}", f"Size: {result.size:,} bytes", f"Type: {result.magic}",
                f"SHA-256: {result.sha256[:32]}...", f"Entropy: {result.entropy:.4f}",
                f"PE Sections: {result.section_count}",]
        
        if result.packer_detected:
            lines.append(f"Packer/Obfuscator detected: {', '.join(result.packer_detected)}")
        
        if result.suspicious_strings:
            unique = set(s[:50] for s in result.suspicious_strings)
            lines.append(f"Suspicious strings found: {len(unique)} unique entries")
        
        return '\n'.join(lines)


# =============================================================================
# Demo / Entry Point
# =============================================================================

if __name__ == '__main__':
    import sys
    
    # Default demo paths - will use system executables if no args provided
    demo_paths = [
        '/bin/ls',           # Linux executable
        '/usr/bin/python3',  # Python interpreter
    ]
    
    # Override with command line arguments if provided
    if len(sys.argv) > 1:
        demo_paths = sys.argv[1:]
    
    print("=" * 60)
    print("Binhunt Binary Fingerprinter - Demo")
    print("=" * 60)
    print()
    
    scanner = BinaryFingerprinter(entropy_threshold=7.5)
    
    for path in demo_paths:
        print(f"\n{'─' * 40}")
        print(f"Scanning: {path}")
        
        try:
            result = scanner.scan(path, deep=True)
            
            print(scanner.get_summary(result))
            print()
            
            # Show detailed info if requested or for demo purposes
            print("Detailed Analysis:")
            print(f"  - Is PE: {result.is_pe}")
            print(f"  - Raw header hash: {result.raw_header_hash[:32]}...")
            
            if result.import_table_hash:
                print(f"  - Import table hash: {result.import_table_hash[:32]}...")
            
            if result.suspicious_strings:
                print("  - Top suspicious strings:")
                for s in result.suspicious_strings[:5]:
                    print(f"    • {s[:60]}{'...' if len(s) > 60 else ''}")
                
        except Exception as e:
            print(f"  Error scanning {path}: {e}")
    
    print("\n" + "=" * 60)
    print("Demo complete.")