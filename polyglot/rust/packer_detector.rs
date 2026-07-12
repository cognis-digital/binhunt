use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Instant;

/// Known packer signatures and their metadata.
#[derive(Debug)]
struct PackerInfo {
    name: &'static str,
    magic_bytes: [u8],
    min_length: usize,
    description: &'static str,
}

impl PackerInfo {
    fn new(name: &str, magic: &[u8], desc: &str) -> Self {
        let min_len = (magic.len() * 2).max(64);
        Self {
            name,
            magic_bytes: magic.to_vec(),
            min_length,
            description: desc,
        }
    }
}

/// Known packers database.
const PACKERS: &[PackerInfo] = &[
    PackerInfo::new(
        "UPX",
        b"\x14\x01\x02", // UPX header magic
        "Ultimate Packer for eXecutables (UPX)",
    ),
    PackerInfo::new(
        "PECompact",
        b"PCOMPACT",
        "PECompact packer",
    ),
    PackerInfo::new(
        "Themepack",
        b"\x02\x14\x05\x00\x03\x00\x00\x00", // Themepack header
        "Themepack (often used with UPX)",
    ),
    PackerInfo::new(
        "ASPack",
        b"ASP",
        "ASPack packer",
    ),
    PackerInfo::new(
        "Themida",
        b"\x02\x14\x05\x00\x03\x00\x00\x00", // Similar to Themepack
        "Themida protection",
    ),
    PackerInfo::new(
        "VMProtect",
        b"VMProt",
        "VMProtect packer/protection",
    ),
    PackerInfo::new(
        "Enigma Protector",
        b"\x02\x14\x05\x00\x03\x00\x00\x00", // Often similar header
        "Enigma Protector",
    ),
];

/// Result of packer detection.
#[derive(Debug, Clone)]
pub struct PackerResult {
    pub is_packed: bool,
    pub detected_packers: Vec<PackerInfo>,
    pub entropy: f64,
    pub file_size: u64,
    pub scan_time_ms: u128,
}

impl Default for PackerResult {
    fn default() -> Self {
        Self::new()
    }
}

impl PackerResult {
    /// Create a new result with defaults.
    fn new() -> Self {
        Self {
            is_packed: false,
            detected_packers: Vec::new(),
            entropy: 0.0,
            file_size: 0,
            scan_time_ms: 0,
        }
    }

    /// Check if a specific packer was detected.
    pub fn has_packer(&self, name: &str) -> bool {
        self.detected_packers.iter().any(|p| p.name == name)
    }

    /// Get the most likely packer (first in list).
    pub fn primary_packer(&self) -> Option<&PackerInfo> {
        self.detected_packers.first()
    }

    /// Calculate entropy for a byte slice.
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u64; 256];
        
        // Count byte frequencies
        for &byte in data.iter().take(1_000_000) {
            counts[byte as usize] += 1;
        }

        // Calculate entropy: -sum(p * log2(p))
        let mut entropy = 0.0f64;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / data.len() as f64;
                entropy -= p * (p.ln() / 8.0); // Convert natural log to base-2
            }
        }

        entropy.min(8.0) // Max theoretical entropy is 8 bits per byte
    }

    /// Check if entropy suggests packing (heuristic).
    fn check_entropy_heuristic(&self, min_entropy: f64) -> bool {
        self.entropy > min_entropy && self.file_size > 1024 * 1024 // > 1MB
    }

    /// Detect packers in a file path.
    pub fn detect_from_path(path: &PathBuf, options: PackerOptions) -> io::Result<Self> {
        let start = Instant::now();
        
        let mut result = Self::new();
        result.file_size = path.metadata()?.len() as u64;

        // Read file in chunks for memory efficiency
        let chunk_size = 1024 * 1024; // 1MB chunks
        let mut reader = File::open(path)?;
        
        // Collect header data (first 8KB is usually enough)
        let mut header_data = [0u8; 8192];
        if reader.read(&mut header_data).map_err(|e| e.into())? > 0 {
            result.entropy = Self::calculate_entropy(&header_data);
            
            // Check for known packer signatures in header
            let mut found_packers: Vec<PackerInfo> = PACKERS.iter()
                .filter(|p| p.min_length <= header_data.len() && 
                           header_data[..p.magic_bytes.len()] == &p.magic_bytes)
                .collect();

            if !found_packers.is_empty() {
                result.detected_packers = found_packers;
                result.is_packed = true;
            } else {
                // Check for resource-based detection (more reliable for some packers)
                let full_data = reader.seek(SeekFrom::Start(0))?;
                
                if full_data > 0x10000 && !result.is_packed {
                    // For PE files, check resources section
                    result.entropy = Self::calculate_entropy(&header_data);
                    
                    // Check for common resource patterns
                    let has_resource_pattern = header_data.windows(4)
                        .any(|w| w[1] == 0x03 && w[2] == 0x00); // RT_GROUP_ICON
                    
                    if has_resource_pattern {
                        result.entropy = Self::calculate_entropy(&header_data);
                        
                        // High entropy + resource pattern often indicates packing
                        let is_suspicious = result.entropy > 6.5;
                        
                        if is_suspicious && options.check_entropy {
                            result.detected_packers.push(
                                PackerInfo::new("Suspicious", b"SUSP", "High-entropy suspicious content")
                            );
                            result.is_packed = true;
                        }
                    }
                }
            }
        }

        let duration_ms = start.elapsed().as_millis();
        result.scan_time_ms = duration_ms as u128;

        Ok(result)
    }

    /// Detect packers from raw bytes.
    pub fn detect_from_bytes(data: &[u8], options: PackerOptions) -> io::Result<Self> {
        let start = Instant::now();
        
        let mut result = Self::new();
        result.file_size = data.len() as u64;
        result.entropy = Self::calculate_entropy(data);

        // Check for known packer signatures
        let mut found_packers: Vec<PackerInfo> = PACKERS.iter()
            .filter(|p| p.min_length <= data.len() && 
                       &data[..p.magic_bytes.len()] == &p.magic_bytes)
            .collect();

        if !found_packers.is_empty() {
            result.detected_packers = found_packers;
            result.is_packed = true;
        } else {
            // Check for resource-based detection
            let has_resource_pattern = data.windows(4)
                .any(|w| w[1] == 0x03 && w[2] == 0x00); // RT_GROUP_ICON
            
            if has_resource_pattern && result.entropy > 6.5 {
                result.detected_packers.push(
                    PackerInfo::new("Suspicious", b"SUSP", "High-entropy suspicious content")
                );
                result.is_packed = true;
            }
        }

        let duration_ms = start.elapsed().as_millis();
        result.scan_time_ms = duration_ms as u128;

        Ok(result)
    }
}

/// Configuration options for packer detection.
#[derive(Debug, Clone)]
pub struct PackerOptions {
    pub check_entropy: bool,
    pub min_file_size: usize,
    pub chunk_size: usize,
}

impl Default for PackerOptions {
    fn default() -> Self {
        Self {
            check_entropy: true,
            min_file_size: 1024 * 1024, // 1MB
            chunk_size: 1024 * 1024,    // 1MB chunks
        }
    }
}

/// Report format for CLI output.
#[derive(Debug)]
pub enum OutputFormat {
    Json,
    Text,
    Compact,
}

impl PackerResult {
    /// Format result as a string based on the selected format.
    pub fn to_string(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self).unwrap_or_else(|_| "Error".into()),
            OutputFormat::Text | OutputFormat::Compact => self.to_text(),
        }
    }

    /// Format as human-readable text.
    fn to_text(&self) -> String {
        let mut output = format!("Packer Detection Result\n");
        output.push_str(&format!("  File Size: {} bytes\n", self.file_size));
        
        if self.is_packed {
            output.push_str("  Status: PACKED\n");
            
            for packer in &self.detected_packers {
                output.push_str(&format!(
                    "    - {}\n", 
                    packer.name
                ));
            }
        } else {
            output.push_str("  Status: NOT PACKED\n");
        }

        if self.check_entropy && self.entropy > 6.0 {
            output.push_str(&format!(
                "  Entropy: {:.2} bits (suspicious)\n", 
                self.entropy
            ));
        } else if self.entropy > 7.5 {
            output.push_str(&format!(
                "  Entropy: {:.2} bits (very high)\n", 
                self.entropy
            ));
        }

        output.push_str(&format!("  Scan Time: {} ms\n", self.scan_time_ms));

        output
    }
}

/// Main entry point for the packer detector tool.
pub fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    // Default to current executable if no arguments provided
    let target_path = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        std::env::current_exe()?.join("binhunt.exe")
    };

    println!("=== Binhunt Packer Detector ===");
    println!("Target: {:?}", target_path);
    
    // Check if file exists
    let metadata = match target_path.metadata() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            return Ok(());
        }
    };

    println!("Size: {} bytes", metadata.len());
    
    // Run detection with default options
    let result = PackerResult::detect_from_path(&target_path, Default::default())?;
    
    println!("\n{}", result.to_text());
    
    // Exit with appropriate code
    if result.is_packed {
        std::process::exit(1);
    } else {
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // All zeros should have 0 entropy
        let zero_data = vec![0u8; 1024];
        assert_eq!(PackerResult::calculate_entropy(&zero_data), 0.0);
        
        // Random data should have high entropy (close to 8)
        let mut rng = rand::thread_rng();
        let random_data: Vec<u8> = (0..1024).map(|_| rng.gen()).collect();
        let entropy = PackerResult::calculate_entropy(&random_data);
        assert!(entropy > 7.5 && entropy <= 8.0);
    }

    #[test]
    fn test_upx_detection() {
        // UPX header is 0x14 0x01 0x02
        let upx_header = vec![0x14, 0x01, 0x02];
        
        let result = PackerResult::detect_from_bytes(&upx_header, Default::default()).unwrap();
        assert!(result.is_packed);
        assert!(result.has_packer("UPX"));
    }

    #[test]
    fn test_empty_file() {
        let empty: Vec<u8> = vec![];
        let result = PackerResult::detect_from_bytes(&empty, Default::default()).unwrap();
        
        assert_eq!(result.file_size, 0);
        assert_eq!(result.entropy, 0.0);
    }

    #[test]
    fn test_result_methods() {
        let mut result = PackerResult::new();
        result.is_packed = true;
        result.detected_packers.push(PackerInfo::new("TestPacker", b"TP", "Test"));
        
        assert!(result.has_packer("TestPacker"));
        assert_eq!(result.primary_packer().unwrap().name, "TestPacker");
    }

    #[test]
    fn test_output_format() {
        let result = PackerResult::new();
        result.is_packed = true;
        result.detected_packers.push(PackerInfo::new("UPX", b"\x14\x01\x02", "UPX"));
        
        let text = result.to_text();
        assert!(text.contains("PACKED"));
        assert!(text.contains("UPX"));
    }
}

fn main() {
    if let Err(e) = main() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}