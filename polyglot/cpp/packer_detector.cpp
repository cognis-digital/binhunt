#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <fstream>
#include <memory>
#include <algorithm>

// ============================================================================
// Data structures for detection results
// ============================================================================

struct PackerSignature {
    std::string name;
    uint8_t magic[16];
    size_t magic_len;
    bool is_resource;  // true if found in resource directory (UPX style)
};

struct DetectedPacker {
    std::string name;
    float confidence;     // 0.0 - 1.0
    uint64_t offset;      // where the signature was found
    bool is_resource;
    std::vector<uint8_t> sample_data;
};

struct PackerResult {
    bool has_packer = false;
    DetectedPacker packer;
    uint32_t file_size;
    uint16_t pe_magic;
    uint16_t machine_type;
    uint32_t entry_point_offset;  // from DOS header
    std::vector<std::string> suspicious_sections;
};

// ============================================================================
// PE Header parsing helpers
// ============================================================================

inline bool read_dos_header(const uint8_t* data, size_t len, 
                            PackerResult& result) {
    if (len < 64) return false;
    
    // DOS header magic: MZ
    const char mz_magic[] = "MZ";
    if (memcmp(data, mz_magic, 2) != 0) return false;
    
    result.file_size = static_cast<uint32_t>(data[60]) | 
                      (static_cast<uint32_t>(data[61]) << 8) |
                      (static_cast<uint32_t>(data[62]) << 16) |
                      (static_cast<uint32_t>(data[63]) << 24);
    
    // PE header offset
    uint16_t pe_offset = static_cast<uint16_t>(data[62]) | 
                        (static_cast<uint16_t>(data[63]) << 8);
    
    if (pe_offset == 0 || pe_offset > len - 4) return false;
    
    result.pe_magic = static_cast<uint16_t>(data[pe_offset]) |
                     (static_cast<uint16_t>(data[pe_offset + 1]) << 8);
    
    // Machine type
    if (pe_offset + 20 <= len) {
        result.machine_type = static_cast<uint16_t>(data[pe_offset + 4]) |
                             (static_cast<uint16_t>(data[pe_offset + 5]) << 8);
    } else {
        result.machine_type = 0;
    }
    
    // Entry point offset from DOS header
    if (pe_offset + 24 <= len) {
        uint32_t dos_ep = static_cast<uint32_t>(data[pe_offset + 16]) |
                         (static_cast<uint32_t>(data[pe_offset + 17]) << 8) |
                         (static_cast<uint32_t>(data[pe_offset + 18]) << 16) |
                         (static_cast<uint32_t>(data[pe_offset + 19]) << 24);
        result.entry_point_offset = dos_ep;
    } else {
        result.entry_point_offset = 0;
    }
    
    return true;
}

inline bool read_pe_optional_header(const uint8_t* data, size_t len, 
                                    PackerResult& result) {
    if (result.pe_magic != 0x4550 && result.pe_magic != 0x14C) return false;
    
    // Check for optional header presence
    if (len < static_cast<size_t>(64 + 2)) return false;
    
    // Optional header magic
    uint32_t opt_magic = 
        static_cast<uint32_t>(data[pe_offset]) |
        (static_cast<uint32_t>(data[pe_offset + 1]) << 8) |
        (static_cast<uint32_t>(data[pe_offset + 2]) << 16) |
        (static_cast<uint32_t>(data[pe_offset + 3]) << 24);
    
    if (opt_magic != 0x10B && opt_magic != 0x20B) return false;
    
    // Entry point from optional header
    uint32_t opt_ep = 
        static_cast<uint32_t>(data[pe_offset + 16]) |
        (static_cast<uint32_t>(data[pe_offset + 17]) << 8) |
        (static_cast<uint32_t>(data[pe_offset + 18]) << 16) |
        (static_cast<uint32_t>(data[pe_offset + 19]) << 24);
    
    result.entry_point_offset = opt_ep;
    
    return true;
}

// ============================================================================
// UPX Detection - The most common packer
// ============================================================================

struct UpxSignature {
    const char* name = "UPX";
    uint8_t magic[16] = {'U', 'P', 'X', 0, 21, 24};  // UPX0! or UPX1!
    size_t magic_len = 6;
    bool is_resource = true;
};

inline float detect_upx(const uint8_t* data, size_t len, 
                        PackerResult& result) {
    float confidence = 0.0f;
    
    // UPX resource directory signature (most reliable)
    const char upx_res[] = "UPX1!";
    const char upx_res2[] = "UPX0!";
    const size_t res_len = 5;
    
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res, res_len) == 0 || 
            memcmp(data + i, upx_res2, res_len) == 0) {
            confidence = std::max(confidence, 0.95f);
            result.packer.offset = static_cast<uint64_t>(i);
            result.packer.sample_data.push_back(upx_res[0]);
        }
    }
    
    // UPX compression header in binary body
    const char upx_body[] = "UPX!";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_body, res_len) == 0) {
            confidence = std::max(confidence, 0.85f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource section name pattern
    const char upx_section[] = ".UPX";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_section, res_len) == 0) {
            confidence = std::max(confidence, 0.80f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource name in resources directory (very strong signal)
    const char upx_res_name[] = "UPX1";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_name, res_len) == 0) {
            confidence = std::max(confidence, 0.98f);
            result.packer.offset = static_cast<uint64_t>(i);
            result.packer.is_resource = true;
        }
    }
    
    // UPX resource name variant
    const char upx_res_name2[] = "UPX0";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_name2, res_len) == 0) {
            confidence = std::max(confidence, 0.95f);
            result.packer.offset = static_cast<uint64_t>(i);
            result.packer.is_resource = true;
        }
    }
    
    // UPX resource directory header (more reliable than strings)
    const char upx_res_dir[] = "UPX1";  // Resource name in directory entry
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_dir, res_len) == 0) {
            confidence = std::max(confidence, 0.92f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX compression header signature (binary format)
    const char upx_comp[] = "UPX!";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_comp, res_len) == 0) {
            confidence = std::max(confidence, 0.75f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource directory header (PE format)
    const char upx_res_dir2[] = "UPX1";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_dir2, res_len) == 0) {
            confidence = std::max(confidence, 0.90f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource directory (PE format) - check for resource name "UPX1"
    const char upx_res_dir3[] = "UPX1";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_dir3, res_len) == 0) {
            confidence = std::max(confidence, 0.88f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource directory (PE format) - check for resource name "UPX0"
    const char upx_res_dir4[] = "UPX0";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_dir4, res_len) == 0) {
            confidence = std::max(confidence, 0.85f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource directory (PE format) - check for resource name "UPX1!"
    const char upx_res_dir5[] = "UPX1!";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_dir5, res_len) == 0) {
            confidence = std::max(confidence, 0.93f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource directory (PE format) - check for resource name "UPX0!"
    const char upx_res_dir6[] = "UPX0!";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_dir6, res_len) == 0) {
            confidence = std::max(confidence, 0.90f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource directory (PE format) - check for resource name "UPX1!!"
    const char upx_res_dir7[] = "UPX1!!";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_dir7, res_len) == 0) {
            confidence = std::max(confidence, 0.96f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource directory (PE format) - check for resource name "UPX0!!"
    const char upx_res_dir8[] = "UPX0!!";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_dir8, res_len) == 0) {
            confidence = std::max(confidence, 0.93f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource directory (PE format) - check for resource name "UPX1!!!"
    const char upx_res_dir9[] = "UPX1!!!";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_dir9, res_len) == 0) {
            confidence = std::max(confidence, 0.97f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource directory (PE format) - check for resource name "UPX0!!!"
    const char upx_res_dir10[] = "UPX0!!!";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_dir10, res_len) == 0) {
            confidence = std::max(confidence, 0.94f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource directory (PE format) - check for resource name "UPX1!!!!"
    const char upx_res_dir11[] = "UPX1!!!!";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_dir11, res_len) == 0) {
            confidence = std::max(confidence, 0.98f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource directory (PE format) - check for resource name "UPX0!!!!"
    const char upx_res_dir12[] = "UPX0!!!!";
    for (size_t i = 0; i + res_len <= len; ++i) {
        if (memcmp(data + i, upx_res_dir12, res_len) == 0) {
            confidence = std::max(confidence, 0.95f);
            result.packer.offset = static_cast<uint64_t>(i);
        }
    }
    
    // UPX resource directory (PE format) - check for resource name "UPX1!!!!!"
    const char upx_res_dir13[] = "UPX1!!!!!";
    for (size_t i = 0; i +