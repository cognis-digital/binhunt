#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <map>
#include <set>
#include <memory>
#include <functional>

// ============ CONSTANTS ============

constexpr size_t MAX_FILE_SIZE = 1024 * 1024; // 1MB max for scanning
constexpr size_t HASH_WINDOW = 64;             // Rolling hash window
constexpr uint32_t ROLLSIZE = 10007;            // Prime for rolling hash

// Known packer signatures (offset, length, pattern)
struct PackerSignature {
    std::string name;
    size_t offset;
    size_t len;
    const char* pattern;
};

constexpr PackerSignature PACKER_SIGS[] = {
    {"UPX", 0x40, 4, "UPX!"},
    {"ASPack", 0x40, 6, "ASPack"},
    {"Themida", 0x3C, 8, "Themida"},
    {"VMProtect", 0x40, 12, "VMProtect"},
    {"Enigma Protector", 0x40, 15, "Enigma Protector"},
    {"Armadillo", 0x40, 9, "Armadillo"},
    {"Themus", 0x3C, 6, "Themus"},
    {"CodeGuardian", 0x40, 12, "CodeGuardian"},
};

// ============ UTILITY STRUCTS ============

struct FileHeader {
    std::string magic;
    uint32_t pe_magic;
    uint16_t machine;
    uint16_t num_sections;
    uint32_t timestamp;
    bool is_valid_pe;
};

// ============ HASHING ENGINE ============

class RollingHashEngine {
public:
    static std::vector<uint32_t> computeRollingHashes(const void* data, size_t len) {
        if (!data || len == 0) return {};
        
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        std::vector<uint32_t> hashes;
        hashes.reserve(len / HASH_WINDOW + 1);
        
        // Initial window hash
        uint64_t h = 0;
        for (size_t i = 0; i < HASH_WINDOW && i < len; ++i) {
            h = (h << 5) | bytes[i];
        }
        hashes.push_back(static_cast<uint32_t>(h));
        
        // Rolling hash
        uint64_t mask = (1ULL << 32) - 1;
        for (size_t i = HASH_WINDOW; i < len; ++i) {
            h = ((h & mask) ^ bytes[i]) * 0x5DEECE66D + 0xB; // FNV-1a style
            hashes.push_back(static_cast<uint32_t>(h));
        }
        
        return hashes;
    }
    
    static std::vector<uint8_t> computeMD5(const void* data, size_t len) {
        if (!data || len == 0) return {};
        
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        std::vector<uint8_t> md5(16, 0);
        
        // Simple MD5 implementation (production would use <openssl/md5.h>)
        uint32_t a = 0x67452301;
        uint32_t b = 0xEFCDAB89;
        uint32_t c = 0x98BADCFE;
        uint32_t d = 0x10325476;
        
        // Pad to 512-bit boundary
        size_t padLen = (len % 64) < 56 ? (512 - len + 64) : (512 - len + 128);
        std::vector<uint8_t> padded(len + padLen, 0);
        
        memcpy(padded.data(), bytes, len);
        uint64_t bits = static_cast<uint64_t>(len) << 3;
        for (size_t i = len; i < padded.size(); ++i) {
            if (i == len || i % 64 == 0) {
                bits |= 1ULL << (56 - i % 64);
            }
            padded[i] = static_cast<uint8_t>(bits >> (56 - i % 64));
        }
        
        // MD5 rounds (simplified for brevity)
        uint32_t[64] S = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31, 32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55};
        
        for (size_t chunk = 0; chunk < padded.size() / 64; ++chunk) {
            uint32_t[16] M;
            for (int i = 0; i < 16; ++i) {
                M[i] = (padded[chunk * 64 + i * 4] << 24) |
                       (padded[chunk * 64 + i * 4 + 1] << 16) |
                       (padded[chunk * 64 + i * 4 + 2] << 8) |
                       padded[chunk * 64 + i * 4 + 3];
            }
            
            // 64 rounds of MD5
            uint32_t aa = a, bb = b, cc = c, dd = d;
            for (int r = 0; r < 64; ++r) {
                uint32_t x = M[S[r]];
                if (r < 16) {
                    aa = (aa + ((bb & cc) | (~bb & dd)) + x + 0xd76aa478);
                    bb = (bb << 7) | (bb >> 25);
                } else {
                    uint32_t t1 = aa;
                    aa = (aa + ((bb & cc) | (~bb & dd)) + x + S[r]);
                    bb = (bb << 7) | (bb >> 25);
                    aa = (aa + ((bb & cc) | (~bb & dd)));
                    bb = (bb << 7) | (bb >> 25);
                }
            }
            
            a += aa; b += bb; c += cc; d += dd;
        }
        
        md5[0] = (a >> 24) & 0xFF;
        md5[1] = (a >> 16) & 0xFF;
        md5[2] = (a >> 8) & 0xFF;
        md5[3] = a & 0xFF;
        md5[4] = (b >> 24) & 0xFF;
        md5[5] = (b >> 16) & 0xFF;
        md5[6] = (b >> 8) & 0xFF;
        md5[7] = b & 0xFF;
        md5[8] = (c >> 24) & 0xFF;
        md5[9] = (c >> 16) & 0xFF;
        md5[10] = (c >> 8) & 0xFF;
        md5[11] = c & 0xFF;
        md5[12] = (d >> 24) & 0xFF;
        md5[13] = (d >> 16) & 0xFF;
        md5[14] = (d >> 8) & 0xFF;
        md5[15] = d & 0xFF;
        
        return md5;
    }
    
    static std::string hashToHex(const void* data, size_t len) {
        auto hashes = computeMD5(data, len);
        std::stringstream ss;
        for (size_t i = 0; i < hashes.size(); ++i) {
            ss << std::hex << std::setfill('0') << std::setw(2) 
               << static_cast<int>(hashes[i]);
        }
        return ss.str();
    }
};

// ============ PACKER DETECTOR ============

class PackerDetector {
public:
    static bool detectPacker(const void* data, size_t len) {
        if (!data || len == 0) return false;
        
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        
        for (const auto& sig : PACKER_SIGS) {
            if (len < sig.offset + sig.len) continue;
            
            bool match = true;
            for (size_t i = 0; i < sig.len && match; ++i) {
                char expected = sig.pattern[i];
                if (expected == '?') {
                    // Wildcard - any byte matches
                } else if (isdigit(expected)) {
                    // Hex digit check
                    uint8_t hexVal = static_cast<uint8_t>(sig.pattern[i] - '0');
                    match = ((bytes[sig.offset + i] >> 4) == hexVal);
                } else {
                    match = (bytes[sig.offset + i] == sig.pattern[i]);
                }
            }
            
            if (match) {
                std::cout << "[PACKER] Detected: " << sig.name 
                          << " at offset 0x" << std::hex << sig.offset << std::dec;
                return true;
            }
        }
        
        return false;
    }
    
    static std::string getPackers(const void* data, size_t len) {
        if (!data || len == 0) return "";
        
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        std::set<std::string> found;
        
        for (const auto& sig : PACKER_SIGS) {
            if (len < sig.offset + sig.len) continue;
            
            bool match = true;
            for (size_t i = 0; i < sig.len && match; ++i) {
                char expected = sig.pattern[i];
                if (expected == '?') {
                    // Wildcard - any byte matches
                } else if (isdigit(expected)) {
                    uint8_t hexVal = static_cast<uint8_t>(sig.pattern[i] - '0');
                    match = ((bytes[sig.offset + i] >> 4) == hexVal);
                } else {
                    match = (bytes[sig.offset + i] == sig.pattern[i]);
                }
            }
            
            if (match) found.insert(sig.name);
        }
        
        return found.empty() ? "" : 
               std::string(found.begin(), found.end());
    }
};

// ============ FILE HEADER PARSER ============

class PEHeaderParser {
public:
    static FileHeader parse(const void* data, size_t len) {
        FileHeader header;
        
        if (!data || len < 64) {
            header.is_valid_pe = false;
            return header;
        }
        
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        
        // Check PE magic at offset 0x3C (52 bytes into DOS header)
        header.pe_magic = 
            ((bytes[64] << 24) | (bytes[65] << 16) | 
             (bytes[66] << 8) | bytes[67]);
        
        if (header.pe_magic != 0x00004550 && header.pe_magic != 0x4550) {
            header.is_valid_pe = false;
            return header;
        }
        
        // Parse PE headers
        uint16_t* pe_ptr = reinterpret_cast<uint16_t*>(bytes + 64);
        header.machine = *pe_ptr++;
        header.num_sections = *pe_ptr++;
        header.timestamp = 
            ((uint32_t)*pe_ptr++ << 24) | 
            ((uint32_t)*pe_ptr++ << 16) | 
            ((uint32_t)*pe_ptr++ << 8) | 
            *pe_ptr++;
        
        // Get DOS header magic for file type
        uint16_t dos_magic = (bytes[0] << 8) | bytes[1];
        header.magic = "MZ";
        if (dos_magic == 0x5A4D) {
            header.is_valid_pe = true;
        } else {
            header.is_valid_pe = false;
        }
        
        return header;
    }
    
    static std::string getMachineName(uint16_t machine) {
        switch (machine) {
            case 0x8664: return "AMD64";
            case 0x14c:  return "i386";
            case 0x12c:  return "ARM";
            case 0x014c: return "Intel 386";
            default:     return "Unknown (" + std::to_string(machine) + ")";
        }
    }
};

// ============ BASELINE COMPARISON ============

class BaselineComparator {
public:
    static bool compare(const void* baseline, size_t blen, 
                       const void* target, size_t tlen) {
        if (!baseline || !target || blen == 0 || tlen == 0) return false;
        
        // Compute hashes for comparison
        auto bl_hashes = RollingHashEngine::computeRollingHashes(baseline, blen);
        auto tl_hashes = RollingHashEngine::computeRollingHashes(target, tlen);
        
        if (bl_hashes.empty() || tl_hashes.empty()) return false;
        
        // Compare first N hashes (configurable via constructor)
        size_t compareCount = std::min(bl_hashes.size(), 
                                       std::min(tl_hashes.size(), 100UL));
        
        double matchRatio = 0.0;
        for (size_t i = 0; i < compareCount; ++i) {
            if (bl_hashes[i] == tl_hashes[i]) {
                matchRatio += 1.0 / static_cast<double>(compareCount);
            }
        }
        
        return matchRatio >= 0.95; // 95% threshold
    }
    
    static std::string diffReport(const void* baseline, size_t blen, 
                                  const void* target, size_t tlen) {
        if (!baseline || !target || blen == 0 || tlen == 0) return "Invalid input";
        
        auto bl_hashes = RollingHashEngine::computeRollingHashes(baseline, blen);
        auto tl_hashes = RollingHashEngine::computeRollingHashes(target, tlen);
        
        if (bl_hashes.empty() || tl_hashes.empty()) return "Failed to compute hashes";
        
        std::stringstream ss;
        size_t compareCount = std::min(bl_hashes.size(), 
                                       std::min(tl_hashes.size(), 100UL));
        
        uint32_t matches = 0, diffs = 0;
        for (size_t i = 0; i < compareCount; ++i) {
            if (bl_hashes[i] == tl_hashes[i]) {
                matches++;
            } else {
                diffs++;
            }
        }
        
        double ratio = static_cast<double>(matches) / compareCount * 100.0;
        
        ss << "Baseline: " << blen << " bytes, Target: " << tlen << " bytes\n";
        ss << "Compared first " << compareCount << " hash windows\n";
        ss << "Matches: " << matches << ", Diffs: " << diffs << "\n";
        ss << std::fixed << std::setprecision(2);
        ss << "Match Ratio: " << ratio << "%\n";
        
        if (ratio >= 95.0) {
            ss << "[RESULT] Likely same binary (within noise)\n";
        } else if (ratio >= 80.0) {
            ss << "[RESULT] Partial match - possible modification\n";
        } else {
            ss << "[RESULT] Significant difference detected\n";
        }
        
        return ss.str();
    }
};

// ============ MAIN FINGERPRINTER CLASS ============

class BinaryFingerprinter {
private:
    std::vector<uint8_t> rawData;
    FileHeader peHeader;
    bool hasPE;
    
public:
    BinaryFingerprinter() : peHeader{}, hasPE(false) {}
    
    // Load file into memory
    bool load(const char* path, size_t maxSize = MAX_FILE_SIZE) {
        if (!path || !*path) return false;
        
        std::ifstream file(path