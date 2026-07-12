package polyglot.java;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.*;
import java.security.MessageDigest;
import java.util.stream.Collectors;

/**
 * Binary Fingerprinter for binhunt tool.
 * 
 * Core capabilities:
 * - SHA-256 hash fingerprinting
 * - PE header parsing and section analysis
 * - Entropy-based packing detection
 * - Known packer signature scanning
 */
public class BinaryFingerprinter {

    private static final int DOS_MAGIC = 0x4D5A;
    private static final int PE_SIGNATURE = 0x00004550;
    
    // Common packer signatures (partial list)
    private static final Set<String> PACKER_SIGNATURES = new HashSet<>(Arrays.asList(
        "UPX", "ASPack", "PECompact2", "Themida", "VMProtect", 
        "Enigma Protector", "Armadillo", "Themis", "Themine",
        "CrypTic", "PEShield", "FSG", "MPRESS", "NITE",
        "ASPack v3.0", "UPX16", "UPX18", "UPX29"
    ));

    public static class FingerprintResult {
        private final String path;
        private final String sha256;
        private final double entropy;
        private final List<String> sections;
        private final Set<String> packerSignaturesFound;
        private final int peSignatureOffset;
        private final boolean isPE;

        public FingerprintResult(String path, String sha256, double entropy, 
                                List<String> sections, Set<String> signatures,
                                int offset, boolean isPE) {
            this.path = path;
            this.sha256 = sha256;
            this.entropy = entropy;
            this.sections = sections;
            this.packerSignaturesFound = signatures;
            this.peSignatureOffset = offset;
            this.isPE = isPE;
        }

        public String getPath() { return path; }
        public String getSha256() { return sha256; }
        public double getEntropy() { return entropy; }
        public List<String> getSections() { return sections; }
        public Set<String> getPackerSignaturesFound() { return packerSignaturesFound; }
        public int getPeSignatureOffset() { return peSignatureOffset; }
        public boolean isPE() { return isPE; }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Path: ").append(path).append("\n");
            sb.append("SHA-256: ").append(sha256.substring(0, 16)).append("...\n");
            sb.append("Entropy: ").append(String.format("%.4f", entropy));
            
            if (entropy > 7.0) {
                sb.append(" [HIGH ENTROPY - possible packing]");
            }

            if (!packerSignaturesFound.isEmpty()) {
                sb.append("\nPacker signatures found: ");
                sb.append(String.join(", ", packerSignaturesFound));
            }

            if (isPE) {
                sb.append("\nPE Header detected at offset ").append(peSignatureOffset);
                sb.append(" with ").append(sections.size()).append(" sections");
            } else {
                sb.append("\nNot a PE file or header not found");
            }

            return sb.toString();
        }
    }

    public static FingerprintResult analyze(String filePath) throws IOException {
        if (!new File(filePath).exists()) {
            throw new FileNotFoundException("File not found: " + filePath);
        }

        long fileSize = new File(filePath).length();
        byte[] data;
        
        try (RandomAccessFile raf = new RandomAccessFile(filePath, "r")) {
            data = raf.readAllBytes();
        }

        // 1. Calculate SHA-256 hash
        String sha256 = computeSha256(data);

        // 2. Calculate Shannon entropy
        double entropy = calculateEntropy(data);

        // 3. Parse PE header if applicable
        int peOffset = -1;
        List<String> sections = new ArrayList<>();
        
        if (isPEFile(data)) {
            peOffset = 64; // PE signature is at offset 0x40 in DOS header
            Map<Integer, String> sectionMap = parsePESections(data);
            for (Map.Entry<Integer, String> entry : sectionMap.entrySet()) {
                sections.add(entry.getKey() + ": " + entry.getValue());
            }
        }

        // 4. Scan for packer signatures in strings and header data
        Set<String> foundSignatures = new HashSet<>();
        
        // Extract printable ASCII strings from the binary
        List<String> asciiStrings = extractAsciiStrings(data, 32);
        for (String s : asciiStrings) {
            if (PACKER_SIGNATURES.contains(s)) {
                foundSignatures.add(s);
            }
        }

        return new FingerprintResult(filePath, sha256, entropy, 
                                   sections, foundSignatures, peOffset, isPEFile(data));
    }

    private static String computeSha256(byte[] data) throws IOException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return bytesToHex(md.digest(data));
    }

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

        return entropy; // Max is ~8.0 for uniform distribution
    }

    private static boolean isPEFile(byte[] data) {
        if (data.length < 64) return false;
        
        int dosMagic = (int) ((data[0] & 0xFF) | 
                            ((data[1] & 0xFF) << 8));
        return dosMagic == DOS_MAGIC && isPEHeaderAt(data, 64);
    }

    private static boolean isPEHeaderAt(byte[] data, int offset) {
        if (data.length < offset + 2) return false;
        
        int peSig = (int) ((data[offset] & 0xFF) | 
                          ((data[offset + 1] & 0xFF) << 8));
        return peSig == PE_SIGNATURE;
    }

    private static Map<Integer, String> parsePESections(byte[] data) {
        Map<Integer, String> sections = new LinkedHashMap<>();
        
        if (data.length < 64 + 20) return sections;

        int offset = 64; // Start of PE header
        
        // Read NumberOfSections from OptionalHeader
        short numSectionsShort = 
            (short) ((data[offset] & 0xFF) | 
                     ((data[offset + 1] & 0xFF) << 8));
        
        if (numSectionsShort > 0 && data.length >= offset + 20 + numSectionsShort * 40) {
            
            // Each section header is 40 bytes
            for (int i = 0; i < numSectionsShort; i++) {
                int nameOffset = offset + 20 + (i * 40);
                
                if (data.length >= nameOffset + 16) {
                    // Read section name (first 8 bytes, null-terminated)
                    StringBuilder name = new StringBuilder();
                    for (int j = 0; j < 8 && nameOffset + j < data.length; j++) {
                        if (data[nameOffset + j] == 0) break;
                        name.append((char) data[nameOffset + j]);
                    }
                    
                    sections.put(i, name.toString());
                }
            }
        }

        return sections;
    }

    private static List<String> extractAsciiStrings(byte[] data, int maxLength) {
        List<String> result = new ArrayList<>();
        
        // Use a sliding window approach to find printable strings
        StringBuilder current = new StringBuilder();
        
        for (int i = 0; i < data.length - 15; i++) {
            byte b = data[i];
            
            if (isPrintable(b)) {
                current.append((char) b);
                
                // Check if we have a complete string
                if (current.length() >= 4 && current.length() <= maxLength) {
                    String candidate = current.toString();
                    
                    // Skip whitespace-only strings
                    if (!candidate.trim().isEmpty()) {
                        result.add(candidate);
                    }
                } else if (current.length() > maxLength + 10) {
                    // Reset on overflow
                    current.setLength(0);
                }
            } else {
                if (current.length() >= 4 && current.length() <= maxLength) {
                    String candidate = current.toString();
                    if (!candidate.trim().isEmpty()) {
                        result.add(candidate);
                    }
                }
                current.setLength(0);
            }
        }

        // Don't forget the last string
        if (current.length() >= 4 && current.length() <= maxLength) {
            String candidate = current.toString();
            if (!candidate.trim().isEmpty()) {
                result.add(candidate);
            }
        }

        return result;
    }

    private static boolean isPrintable(byte b) {
        // Printable ASCII: space (32) through tilde (126)
        int val = b & 0xFF;
        return val >= 32 && val <= 126;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    // Demo/Entry point
    public static void main(String[] args) throws Exception {
        System.out.println("=== binhunt Binary Fingerprinter ===\n");

        // Create a test binary (simple PE stub for demonstration)
        String testPath = "test_binary.bin";
        
        try {
            byte[] peStub = createPEStub();
            
            // Write the test file
            Files.write(Paths.get(testPath), peStub);
            System.out.println("Created test PE binary: " + testPath);

            // Analyze our own stub
            FingerprintResult result = analyze(testPath);
            System.out.println("\n--- Analysis Result ---\n");
            System.out.println(result);

            // Create a baseline (known-good version)
            String baselinePath = "baseline.bin";
            Files.write(Paths.get(baselinePath), peStub);
            
            FingerprintResult baseline = analyze(baselinePath);
            System.out.println("\n--- Baseline Comparison ---\n");
            System.out.println("Baseline SHA-256: " + baseline.getSha256());
            System.out.println("Test SHA-256:     " + result.getSha256());

            // Compare hashes
            boolean match = baseline.getSha256().equals(result.getSha256());
            System.out.println("\nHash Match: " + (match ? "YES" : "NO"));
            
            if (!match) {
                System.out.println("Possible tampering detected!");
            }

        } finally {
            // Cleanup test files
            new File(testPath).delete();
            new File(baselinePath).delete();
        }

        System.out.println("\n=== Demo Complete ===");
    }

    private static byte[] createPEStub() throws IOException {
        // Create a minimal valid PE stub for testing
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        // DOS Header (64 bytes)
        // e_magic: MZ
        baos.write(new byte[]{0x4D, 0x5A});
        
        // e_cblp: 0x002C (44 bytes)
        baos.write(new short[]{(short) 0x002C});
        
        // e_cp: 0x01FE (510 bytes)
        baos.write(new short[]{(short) 0x01FE});
        
        // e_cparhdr: 0x0040 (64 bytes)
        baos.write(new short[]{(short) 0x0040});
        
        // e_palign: 0x0020 (32 bytes)
        baos.write(new short[]{(short) 0x0020});
        
        // e_ss: 0x1000 (4096)
        baos.write(new short[]{(short) 0x1000, (short) 0x0000});
        
        // e_sp: 0x0000
        baos.write(new short[]{(short) 0x0000, (short) 0x0000});
        
        // e_csum: 0x0000
        baos.write(new short[]{(short) 0x0000, (short) 0x0000});
        
        // e_ip: 0x1400
        baos.write(new short[]{(short) 0x1400, (short) 0x0000});
        
        // e_cs: 0x1000
        baos.write(new short[]{(short) 0x1000, (short) 0x0000});
        
        // e_lfarlc: 0x0040
        baos.write(new short[]{(short) 0x0040, (short) 0x0000});
        
        // e_ovno: 0x0000
        baos.write(new short[]{(short) 0x0000, (short) 0x0000});
        
        // e_res1-4: padding
        byte[] res = new byte[28];
        for (int i = 0; i < 28; i++) {
            baos.write((byte) 0);
        }

        // PE Header at offset 64
        // e_magic: PE\0\0
        baos.write(new byte[]{0x00, 0x45, 0x50, 0x00});
        
        // e_lfanew: 64 (offset to PE header)
        baos.write(new int[]{0x0040, 0x0000, 0x0000, 0x0000});

        // Optional Header - minimal valid structure
        short magic = 0x010B; // PE32+ (64-bit)
        baos.write(magic);
        
        short pe32PlusHeaderSize = 240;
        baos.write(pe32PlusHeaderSize);
        
        short pe32PlusFlags = 0x0200; // IMAGE_NT_OPTIONAL_HDR64_MAGIC
        baos.write(pe32PlusFlags);

        // Rest of optional header (minimal)
        int[] padding = new int[15];
        for (int i = 0; i < 15; i++) {
            baos.write(padding[i]);
        }

        // Section headers - add a couple sections
        // Section 1: .text
        byte[] textSection = new byte[]{
            't', 'e', 'x', 't', 0, 0, 0, 0,    // Name
            (byte) 0x60, (byte) 0x02,          // Characteristics: CODE | EXECUTE | READ
            0x14, 0x00, 0x00, 0x00,            // VirtualSize
            0x14, 0x00, 0x00, 0x00,            // VirtualAddress
            (byte) 0xE8, (byte) 0x00,          // SizeOfRawData
            0x2C, 0x00, 0x00, 0x00             // PointerToRawData
        };
        
        // Section 2: .