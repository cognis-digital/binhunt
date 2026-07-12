package polyglot.java;

import java.io.*;
import java.nio.*;
import java.nio.channels.Channels;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Packer Detector for binhunt tool.
 * Detects common packers/obfuscators by scanning magic bytes, strings, entropy patterns, and headers.
 */
public class PackerDetector {

    // Known packer signatures (magic bytes, strings)
    private static final Map<String, byte[]> PACKER_SIGNATURES = new HashMap<>();
    
    // Common packer name strings to search for
    private static final Set<String> PACKER_NAMES = new HashSet<>(Arrays.asList(
        "UPX", "UPX16", "UPX20", "Themida", "ASPack", "PECompact", 
        "VMProtect", "Enigma", "Armadillo", "PESymantec", "ThnProtect",
        "CrypTic", "Nisus", "Mars", "VirusTotal"
    ));

    // Entropy thresholds (Shannon entropy 0-8)
    private static final double HIGH_ENTROPY_THRESHOLD = 7.5;
    private static final double PACKED_SECTION_THRESHOLD = 7.2;

    public record ScanResult(
        boolean isPacked,
        List<PackerMatch> matches,
        double overallEntropy,
        String detectedPacker,
        int suspiciousSectionsCount,
        byte[] sampleData
    ) {}

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        // Demo: scan a real binary if provided, otherwise use embedded test data
        File target = new File(args.length > 0 ? args[0] : "test_binary.bin");
        
        if (!target.exists()) {
            System.out.println("No target file. Using embedded test pattern.");
            byte[] testData = createTestPattern();
            target = new File("test_binary.bin");
            try (FileOutputStream out = new FileOutputStream(target)) {
                out.write(testData);
            }
        }

        ScanResult result = scanBinary(target, 4096); // 4KB sample for demo
        
        System.out.println("\n=== PACKER DETECTION RESULTS ===");
        System.out.printf("File: %s\n", target.getAbsolutePath());
        System.out.printf("Overall Entropy: %.2f\n", result.overallEntropy());
        System.out.printf("Is Packed: %b\n", result.isPacked());
        System.out.printf("Suspicious Sections: %d\n", result.suspiciousSectionsCount());
        
        if (result.detectedPacker() != null) {
            System.out.println("Detected Packer: " + result.detectedPacker());
        }

        if (!result.matches().isEmpty()) {
            System.out.println("\nMatches Found:");
            for (PackerMatch m : result.matches()) {
                System.out.printf("  - %s at offset 0x%08X\n", 
                    m.name(), Long.toHexString(m.offset()));
            }
        }

        if (result.isPacked() && result.suspiciousSectionsCount() > 0) {
            System.out.println("\nRecommendation: Run baseline diff or quarantine for analysis.");
        } else {
            System.out.println("\nStatus: Appears to be a normal/unpacked binary.");
        }

        // Cleanup test file if created in memory
        if (target.getName().equals("test_binary.bin") && target.length() < 1024) {
            target.delete();
        }
    }

    /**
     * Main scanning entry point.
     */
    public static ScanResult scanBinary(File binary, int sampleSize) throws IOException {
        long fileSize = binary.length();
        byte[] data;
        
        if (sampleSize > 0 && fileSize < sampleSize) {
            // Read entire file for small files
            try (FileInputStream fis = new FileInputStream(binary)) {
                data = fis.readAllBytes();
            }
        } else {
            // Stream-based sampling for large files
            try (RandomAccessFile raf = new RandomAccessFile(binary, "r");
                 InputStream is = Channels.newChannel(raf.getChannel())
                         .mapToByteBuffer()
                         .slice(fileSize - sampleSize, sampleSize);) {
                data = is.array();
            }
        }

        // Run all detection passes
        List<PackerMatch> matches = new ArrayList<>();
        
        // Pass 1: Magic byte and signature scanning
        matches.addAll(scanMagicBytes(data));
        
        // Pass 2: String-based packer name detection
        matches.addAll(scanPackerNames(data));
        
        // Pass 3: Entropy analysis of sections (PE format)
        double entropy = calculateEntropy(data);
        List<PackerMatch> entropyMatches = scanEntropyPatterns(data, entropy);
        matches.addAll(entropyMatches);
        
        // Pass 4: Header field inspection for PE files
        if (isPEFile(data)) {
            matches.addAll(scanPEHeaders(data));
        }

        // Determine primary detected packer
        String detectedPacker = detectPrimaryPacker(matches, data.length);
        
        // Calculate suspicious section count
        int suspiciousSections = countSuspiciousSections(entropyMatches);
        
        return new ScanResult(
            matches.size() > 0 || entropy >= HIGH_ENTROPY_THRESHOLD || suspiciousSections > 2,
            matches,
            entropy,
            detectedPacker,
            suspiciousSections,
            data.length < sampleSize ? data : null // Return full data only for small files
        );
    }

    /**
     * Scan for known packer magic bytes and signatures.
     */
    private static List<PackerMatch> scanMagicBytes(byte[] data) {
        List<PackerMatch> matches = new ArrayList<>();
        
        // UPX signature: "UPX!" at offset 0x18 in PE headers (common location)
        if (data.length > 0x20) {
            byte[] upxSig = new byte[]{(byte)'U', (byte)'P', (byte)'X', '!'};
            int pos = data.indexOf(upxSig, 0x18); // Start after PE header
            if (pos >= 0x18 && pos < Math.min(data.length, 0x20 + upxSig.length)) {
                matches.add(new PackerMatch("UPX", pos));
            }
        }

        // Generic high-entropy region detection in first 64KB
        if (data.length > 65536) {
            byte[] head = Arrays.copyOfRange(data, 0, 65536);
            double headEntropy = calculateEntropy(head);
            if (headEntropy >= PACKED_SECTION_THRESHOLD) {
                matches.add(new PackerMatch("High-Entropy Header", 0));
            }
        }

        return matches;
    }

    /**
     * Scan for packer name strings embedded in the binary.
     */
    private static List<PackerMatch> scanPackerNames(byte[] data) {
        List<PackerMatch> matches = new ArrayList<>();
        
        // Search for known packer names (case-insensitive, partial match ok)
        for (String name : PACKER_NAMES) {
            int pos = -1;
            
            // Try exact match first
            byte[] bytes = name.getBytes(StandardCharsets.US_ASCII);
            pos = data.indexOf(bytes);
            
            if (pos >= 0) {
                matches.add(new PackerMatch(name, pos));
                continue;
            }

            // Try case-insensitive search in reasonable range
            for (int start = 0x1000; start < Math.min(data.length - name.length(), 0x20000); 
                 start += 4096) {
                byte[] sub = Arrays.copyOfRange(data, start, start + name.length());
                if (isSubstring(sub, bytes)) {
                    matches.add(new PackerMatch(name, start));
                    break;
                }
            }
        }

        return matches;
    }

    /**
     * Calculate Shannon entropy of byte array.
     */
    private static double calculateEntropy(byte[] data) {
        if (data.length == 0) return 0.0;
        
        int[] freq = new int[256];
        for (byte b : data) {
            freq[b & 0xFF]++;
        }

        double entropy = 0.0;
        double total = data.length;
        
        for (int count : freq) {
            if (count > 0) {
                double p = (double) count / total;
                entropy -= p * Math.log(p);
            }
        }

        return entropy;
    }

    /**
     * Scan data for entropy anomalies that suggest packing.
     */
    private static List<PackerMatch> scanEntropyPatterns(byte[] data, double overallEntropy) {
        List<PackerMatch> matches = new ArrayList<>();
        
        // Check if file is PE format and analyze sections
        if (isPEFile(data)) {
            int peOffset = 0x40; // Standard PE header offset
            
            if (data.length > peOffset + 2) {
                short machineType = getShort(data, peOffset);
                
                // Machine type 0x14C = x86, 0x8664 = x64
                boolean isX86OrX64 = (machineType == 0x14C || machineType == 0x8664);
                
                if (isX86OrX64) {
                    // Check for packed flag in PE header
                    int flagsOffset = peOffset + 60;
                    if (data.length > flagsOffset) {
                        int flags = getInt(data, flagsOffset);
                        
                        // Packed bit is bit 31 (0x80000000)
                        if ((flags & 0x80000000) != 0) {
                            matches.add(new PackerMatch("PE Header: Packed Flag", peOffset));
                        }
                    }
                }
            }
        }

        // Check for high-entropy data regions (common in packed files)
        int chunkSize = 4096;
        double chunkThreshold = PACKED_SECTION_THRESHOLD - 0.3; // Slightly lower for chunks
        
        for (int i = 0x1000; i < Math.min(data.length, 0x20000); i += chunkSize) {
            byte[] chunk = Arrays.copyOfRange(data, i, i + chunkSize);
            double chunkEntropy = calculateEntropy(chunk);
            
            if (chunkEntropy >= chunkThreshold && overallEntropy < HIGH_ENTROPY_THRESHOLD) {
                matches.add(new PackerMatch("High-Entropy Chunk", i));
            }
        }

        return matches;
    }

    /**
     * Scan PE headers for additional packer indicators.
     */
    private static List<PackerMatch> scanPEHeaders(byte[] data) {
        List<PackerMatch> matches = new ArrayList<>();
        
        if (!isPEFile(data)) {
            return matches;
        }

        int peOffset = 0x40;
        int headerSize = getShort(data, peOffset + 6); // PE header size
        
        if (data.length < peOffset + headerSize) {
            return matches;
        }

        // Check for common packer-modified fields
        int flags = getInt(data, peOffset + 60);
        
        // Bit 31: Packed flag
        if ((flags & 0x80000000) != 0) {
            matches.add(new PackerMatch("PE Header", peOffset, "Packed Flag Set"));
        }

        // Check section headers for obfuscated names or high entropy
        int numSections = getShort(data, peOffset + 2);
        int sectionsStart = peOffset + 64;
        
        if (data.length >= sectionsStart + numSections * 40) {
            for (int i = 0; i < numSections && i < 100; i++) {
                int sectionNameOffset = sectionsStart + i * 40;
                
                // Extract first few bytes of section name
                byte[] nameBytes = Arrays.copyOfRange(data, 
                    sectionNameOffset, Math.min(sectionNameOffset + 8, data.length));
                
                String name = new String(nameBytes, StandardCharsets.US_ASCII).trim();
                
                // Check for obfuscated/short names (common in packed files)
                if (name.isEmpty() || name.length() < 3 || 
                    name.length() > 15 && !isReadableName(name)) {
                    matches.add(new PackerMatch("PE Header", sectionNameOffset, 
                        "Suspicious Section Name: \"" + name + "\""));
                }

                // Check section characteristics
                int flags = getInt(data, sectionNameOffset + 2);
                
                // Read-only and compressed sections are suspicious
                if ((flags & 0x80000000) != 0 || (flags & 0x40000000) != 0) {
                    matches.add(new PackerMatch("PE Header", sectionNameOffset, 
                        "Compressed/RO Section"));
                }

                // Check for high entropy in code sections
                int virtualSize = getInt(data, sectionNameOffset + 16);
                if (virtualSize > 0 && virtualSize < data.length) {
                    byte[] sectionData = Arrays.copyOfRange(
                        data, 
                        Math.max(peOffset + headerSize, sectionNameOffset),
                        Math.min(sectionNameOffset + virtualSize, data.length));
                    
                    double secEntropy = calculateEntropy(sectionData);
                    if (secEntropy >= PACKED_SECTION_THRESHOLD) {
                        matches.add(new PackerMatch("PE Header", sectionNameOffset, 
                            "High-Entropy Section"));
                    }
                }
            }
        }

        return matches;
    }

    /**
     * Determine the primary detected packer from all matches.
     */
    private static String detectPrimaryPacker(List<PackerMatch> matches, int fileSize) {
        // Priority order for detection confidence
        if (matches.stream().anyMatch(m -> m.name().equals("UPX"))) {
            return "UPX";
        }

        if (matches.stream().anyMatch(m -> m.name().contains("PE Header: Packed Flag"))) {
            return "Unknown PE Packer";
        }

        // Check for specific packer strings with high confidence
        String[] highConfidence = {"VMProtect", "Themida", "Armadillo"};
        for (String p : highConfidence) {
            if (matches.stream().anyMatch(m -> m.name().equals(p))) {
                return p;
            }
        }

        // Fallback: most frequent match name
        Map<String, Integer> freq = matches.stream()
            .collect(Collectors.groupingBy(PackerMatch::name, Collectors.counting()));
        
        if (!freq.isEmpty()) {
            String topPacker = freq.entrySet().stream()
                .max(Comparator.comparingInt(Map.Entry::getValue))
                .map(Map.Entry::getKey)
                .orElse(null);
            
            // Only return if it's a known packer and appears multiple times
            if (topPacker != null && topPacker.contains("PE") && freq.get(topPacker) >= 2) {
                return "Unknown PE Packer";
            }
        }

        return matches.isEmpty() ? null : 
               matches.stream().map(PackerMatch::name).distinct().limit(3).collect(Collectors.joining(", "));
    }

    /**
     * Count sections with suspicious characteristics.
     */
    private static int countSuspiciousSections(List<PackerMatch> entropyMatches) {
        Set<Integer> suspiciousOffsets = new HashSet<>();
        
        for (PackerMatch m : entropyMatches) {
            if (m.name().contains("PE Header") || 
                m.name().contains("High-Entropy")) {
                int offset = m.offset() & 0xFFFF; // PE sections are at offsets like 0x1000, 0x2000
                
                // Map section header offsets to their virtual addresses
                // Section headers start after the main PE header
                int peHeaderSize = getShort(new byte[]{(byte)0x4D, (byte)'P', (byte)'E'}, 6);
                
                if (offset > 0x1000 && offset < 0x20000) {
                    suspiciousOffsets.add(offset &