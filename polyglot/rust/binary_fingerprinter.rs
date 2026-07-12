use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Configuration for the fingerprinter
#[derive(Debug, Clone)]
pub struct FingerprintConfig {
    pub include_strings: bool,
    pub min_string_len: usize,
    pub detect_entropy_threshold: f32,
    pub section_names_to_check: Vec<String>,
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            include_strings: true,
            min_string_len: 4,
            detect_entropy_threshold: 7.5,
            section_names_to_check: vec![
                ".text", ".data", ".rdata", ".idata", ".reloc",
                ".bss", ".sdata", ".sdata2", ".got", ".plt",
            ],
        }
    }
}

/// A single extracted feature from a binary
#[derive(Debug, Clone)]
pub struct Feature {
    pub name: String,
    pub value: String,
    pub source: FeatureSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureSource {
    Header,
    SectionName,
    ImportTable,
    StringTable,
    EntryPoint,
    Other(String),
}

/// Complete fingerprint of a binary
#[derive(Debug, Default)]
pub struct BinaryFingerprint {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub timestamp: SystemTime,
    pub magic_bytes: Vec<u8>,
    pub arch: Option<String>,
    pub entry_point: Option<u64>,
    pub sections: Vec<SectionInfo>,
    pub imports: HashMap<String, usize>, // name -> count
    pub strings: Vec<String>,
    pub entropy: f32,
    pub checksums: Checksums,
    pub features: Vec<Feature>,
}

#[derive(Debug)]
pub struct SectionInfo {
    pub name: String,
    pub size: u64,
    pub vaddr: u64,
    pub rva: u64,
    pub flags: u32,
}

#[derive(Debug, Default)]
pub struct Checksums {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub crc32: Option<u32>,
}

/// Source of a detected feature
#[derive(Debug, Clone)]
pub enum DetectedFeatureType {
    KnownPacker(String),
    ObfuscatedString(usize),
    SuspiciousSectionName(String),
    HighEntropyRegion(u64, u64),
    MissingExpectedSection(String),
}

/// Result of scanning a binary for known packers/obfuscators
pub struct PackerDetection {
    pub detected: Vec<DetectedFeatureType>,
    pub confidence_score: f32, // 0.0 to 1.0
}

impl BinaryFingerprint {
    /// Create a new fingerprinter with default config
    pub fn new() -> Self {
        let mut fp = BinaryFingerprint::default();
        fp.features.push(Feature {
            name: "Config".to_string(),
            value: format!("{:#?}", FingerprintConfig::default()),
            source: FeatureSource::Other("Default".into()),
        });
        fp
    }

    /// Load a binary file and extract its fingerprint
    pub fn load<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut buf = Vec::new();
        fs::read(path)?;
        
        let mut fp = Self::default();
        fp.file_path = path.as_ref().to_path_buf();
        fp.file_size = buf.len() as u64;
        fp.timestamp = SystemTime::now();
        fp.magic_bytes = buf[0..16].to_vec();
        
        let file_info = FileInfo { data: &buf };
        fp.arch = file_info.detect_architecture(&fp.magic_bytes);
        fp.entry_point = file_info.extract_entry_point(&fp.magic_bytes, fp.arch.as_deref());
        fp.sections = file_info.parse_sections(&fp.magic_bytes, fp.arch.as_deref());
        
        let (imports, strings) = file_info.analyze_content(&buf)?;
        fp.imports = imports;
        fp.strings = strings;
        
        fp.entropy = file_info.calculate_entropy(&buf);
        fp.checksums = Checksums::compute_all(&buf);
        
        // Extract additional features
        fp.features.extend(file_info.extract_features());
        
        Ok(fp)
    }

    /// Compare this fingerprint against a baseline and return differences
    pub fn diff<B: AsRef<BinaryFingerprint>>(
        &self,
        baseline: B,
    ) -> DiffResult {
        let baseline = baseline.as_ref();
        let mut diffs = Vec::new();

        // Check magic bytes
        if self.magic_bytes != baseline.magic_bytes.clone() {
            diffs.push(DiffItem {
                field: "MagicBytes".to_string(),
                expected: format!("{:02x?}", &baseline.magic_bytes),
                actual: format!("{:02x?}", &self.magic_bytes),
                severity: Severity::High,
            });
        }

        // Check file size
        if self.file_size != baseline.file_size {
            diffs.push(DiffItem {
                field: "FileSize".to_string(),
                expected: format!("{}", baseline.file_size),
                actual: format!("{}", self.file_size),
                severity: Severity::Medium,
            });
        }

        // Check entry point
        if let (Some(ep1), Some(ep2)) = (&self.entry_point, &baseline.entry_point) {
            if ep1 != ep2 {
                diffs.push(DiffItem {
                    field: "EntryPoint".to_string(),
                    expected: format!("0x{:x}", ep2),
                    actual: format!("0x{:x}", ep1),
                    severity: Severity::High,
                });
            }
        }

        // Check sections
        let baseline_sections: HashSet<_> = baseline.sections.iter()
            .map(|s| s.name.as_str())
            .collect();
        
        for section in &self.sections {
            if !baseline_sections.contains(&section.name) {
                diffs.push(DiffItem {
                    field: format!("Section:{}", section.name),
                    expected: "Present".to_string(),
                    actual: "Missing".to_string(),
                    severity: Severity::High,
                });
            }
        }

        // Check imports
        for (name, count) in &self.imports {
            if let Some(&baseline_count) = baseline.imports.get(name.as_str()) {
                if *count != baseline_count {
                    diffs.push(DiffItem {
                        field: format!("Import:{}", name),
                        expected: format!("{}", baseline_count),
                        actual: format!("{}", count),
                        severity: Severity::Medium,
                    });
                }
            } else {
                diffs.push(DiffItem {
                    field: format!("Import:{}", name),
                    expected: "Present".to_string(),
                    actual: "New".to_string(),
                    severity: Severity::Low,
                });
            }
        }

        // Check entropy change (sudden increase = possible obfuscation)
        let entropy_delta = self.entropy - baseline.entropy;
        if entropy_delta > 0.5 {
            diffs.push(DiffItem {
                field: "EntropyDelta".to_string(),
                expected: format!("{:.2}", entropy_delta),
                actual: format!("> 0.5 (suspicious)", ""),
                severity: Severity::Medium,
            });
        }

        DiffResult { diffs, baseline_checksum: baseline.checksums.sha256.clone() }
    }

    /// Detect if binary uses a known packer or obfuscator
    pub fn detect_packers(&self) -> PackerDetection {
        let mut detected = Vec::new();
        let mut confidence = 0.0;

        // Check for common packer signatures in strings and headers
        let packer_signatures: &[&[u8]] = &[
            b"UPX", b"ASPack", b"PECompact2", b"Themida", b"VMProtect",
            b"Enigma Protector", b"CyberLink", b"Armadillo",
        ];

        for sig in packer_signatures {
            if self.magic_bytes.contains(&sig[0]) && 
               self.magic_bytes.len() >= sig.len() &&
               &self.magic_bytes[..sig.len()] == *sig {
                detected.push(DetectedFeatureType::KnownPacker(
                    format!("{} (detected in header)", String::from_utf8_lossy(sig))
                ));
                confidence = 0.9;
            }

            // Also check strings for packer names
            if let Some(pos) = self.strings.iter()
                .position(|s| s.contains(&String::from_utf8_lossy(sig).to_string())) {
                    detected.push(DetectedFeatureType::ObfuscatedString(pos));
                    confidence = (confidence + 0.15).min(1.0);
            }
        }

        // Check for high entropy regions that might indicate encryption
        if self.entropy > self.detect_entropy_threshold() {
            detected.push(DetectedFeatureType::HighEntropyRegion(
                0, self.file_size
            ));
            confidence = (confidence + 0.2).min(1.0);
        }

        // Check for suspicious section names
        let suspicious_sections: &[&str] = &["packed", "compressed", "encrypted", 
                                             "crypto", "aes"];
        
        for sec in &self.sections {
            if suspicious_sections.iter().any(|s| sec.name.contains(*s)) {
                detected.push(DetectedFeatureType::SuspiciousSectionName(
                    sec.name.clone()
                ));
                confidence = (confidence + 0.1).min(1.0);
            }
        }

        PackerDetection { detected, confidence: confidence.min(1.0) }
    }

    /// Get a human-readable summary of the fingerprint
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        
        lines.push(format!("File: {}", self.file_path.display()));
        lines.push(format!("Size: {} bytes", self.file_size));
        lines.push(format!("Timestamp: {:?}", self.timestamp));
        lines.push(format!("Architecture: {:?}", self.arch.as_deref().unwrap_or("Unknown")));
        lines.push(format!("Magic: {:02x?}", &self.magic_bytes[..std::cmp::min(16, self.magic_bytes.len())]));

        if let Some(ep) = self.entry_point {
            lines.push(format!("EntryPoint: 0x{:x}", ep));
        }

        lines.push(format!("Entropy: {:.3} bits/byte", self.entropy));

        if !self.sections.is_empty() {
            lines.push(format!("\nSections ({})", self.sections.len()));
            for sec in &self.sections {
                lines.push(format!(
                    "  {} - vaddr=0x{:x}, size={}, flags={:08x}",
                    sec.name, sec.vaddr, sec.size, sec.flags
                ));
            }
        }

        if !self.imports.is_empty() {
            let total_imports: usize = self.imports.values().sum();
            lines.push(format!("\nImports: {} unique names, {} total imports", 
                             self.imports.len(), total_imports));
        }

        if self.strings.len() > 100 {
            lines.push(format!("\nStrings: {} total (showing first 100)", self.strings.len()));
            for s in &self.strings[..std::cmp::min(100, self.strings.len())] {
                lines.push(format!("  \"{}\"", s));
            }
        } else if !self.strings.is_empty() {
            lines.push(format!("\nStrings:"));
            for s in &self.strings {
                lines.push(format!("  \"{}\"", s));
            }
        }

        lines.push("\nChecksums:".to_string());
        if let Some(ref md5) = self.checksums.md5 {
            lines.push(format!("  MD5: {}", md5));
        }
        if let Some(ref sha1) = self.checksums.sha1 {
            lines.push(format!("  SHA1: {}", sha1));
        }
        if let Some(ref sha256) = self.checksums.sha256 {
            lines.push(format!("  SHA256: {}", sha256));
        }

        if !self.features.is_empty() {
            lines.push("\nFeatures:".to_string());
            for f in &self.features {
                lines.push(format!("  [{}] {} = {}", 
                                 match &f.source {
                                     FeatureSource::Header => "Header",
                                     FeatureSource::SectionName => "SectionName",
                                     FeatureSource::ImportTable => "ImportTable",
                                     FeatureSource::StringTable => "StringTable",
                                     FeatureSource::EntryPoint => "EntryPoint",
                                     FeatureSource::Other(ref s) => s,
                                 }, 
                                 f.name, f.value);
            }
        }

        lines.join("\n")
    }
}

impl Default for BinaryFingerprint {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper struct to parse binary headers without loading entire file into memory
struct FileInfo<'a> {
    data: &'a [u8],
}

impl<'a> FileInfo<'a> {
    /// Detect the architecture from magic bytes
    fn detect_architecture(&self, magic: &[u8]) -> Option<String> {
        // PE32/PE64 (Windows)
        if magic.len() >= 4 && &magic[0..2] == b"MZ" {
            return Some("x86/x64".to_string());
        }

        // ELF (Linux/BSD/macOS)
        if magic.len() >= 16 && &magic[0..16] == b"\x7fELF" {
            let class = match magic[4] {
                1 => "32-bit",
                2 => "64-bit",
                _ => "unknown",
            };
            return Some(format!("ELF ({})", class));
        }

        // Mach-O (macOS/iOS)
        if magic.len() >= 8 && &magic[0..2] == b"\xfe\xef" {
            return Some("Mach-O".to_string());
        }

        None
    }

    /// Extract entry point based on architecture
    fn extract_entry_point(&self, magic: &[u8], arch: Option<&str>) -> Option<u64> {
        if let (true, Some(arch)) = (magic.len() >= 2, arch) {
            // PE entry point is at offset 0x3C + 0x10
            if &magic[0..2] == b"MZ" && self.data.len() > 0x48 {
                let offset = 0x3C + 0x10;
                if offset < self.data.len() {
                    let ep = u64::from_le_bytes(
                        [self.data[offset], self.data[offset+1], 
                         self.data[offset+2], self.data[offset+3]]
                    );
                    return Some(ep);
                }
            }

            // ELF entry point is in e_entry field (offset 0x18 for 64-bit, 0x1C for 32-bit)
            if arch == "ELF (64-bit)" && self.data.len() > 0x20 {
                let offset = 0x20; // e_entry for 64-bit ELF
                if offset < self.data.len() {
                    let ep = u64::from_le_bytes(
                        [self.data[offset], self.data[offset+1], 
                         self.data[offset+2], self.data[offset+3]]
                    );
                    return Some(ep);
                }
            }
        }

        None
    }

    /// Parse section headers from PE file
    fn parse_sections(&self, magic: &[u8], arch: Option<&str>) -> Vec<SectionInfo> {
        let mut sections = Vec::new();

        if &magic[0..2] == b"MZ" && self.data.len() > 0x48 {
            // PE header offset
            let pe_offset = u16::from_le_bytes([self.data[0x3C], self.data[0x3D]]) as usize;
            
            if pe_offset + 2 < self.data.len() && 
               &self.data[pe_offset..pe_offset+2] == b"PE\0\0" {
                
                // PE header size is at offset 0x18 within PE header
                let pe_header_size = u32::from_le_bytes(
                    [self.data[pe_offset + 0x18], self.data[pe_offset+0x19],
                     self.data[pe_offset+0x1A], self.data[pe_offset+0x1B]]
                ) as usize;

                if pe_header_size >