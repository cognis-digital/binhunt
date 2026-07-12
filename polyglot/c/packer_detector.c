/*
 * binhunt/polyglot/c/packer_detector.c
 * 
 * Packer/Obfuscator Detector Module
 * 
 * Detects common packers and obfuscators by analyzing:
 * - ELF header signatures and sections
 * - PE headers and resource strings  
 * - File entropy (compression indicators)
 * - Known packer string patterns
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* Configuration constants */
#define MAX_FILE_SIZE    (1024 * 1024)      /* 1MB max for scanning */
#define ENTROPY_THRESHOLD 7.5                /* High entropy threshold */
#define STRING_SCAN_LEN  64                  /* Max string length to scan */

/* Packer signatures database */
typedef struct {
    const char *name;
    size_t len;
} PackerSignature;

static PackerSignature PACKER_SIGNATURES[] = {
    {"UPX", 3},
    {"ASPack", 6},
    {"PECompact", 9},
    {"Themida", 7},
    {"VMProtect", 10},
    {"Enigma Protector", 18},
    {"Armadillo", 10},
    {"FSG", 3},
    {"Thew", 4},
    {"MPRESS", 6},
    {"PESimp", 7},
    {"PECompact2", 11},
    {"ASPack2", 7},
    {"Themida2", 9},
    {NULL, 0}
};

/* ELF magic bytes */
#define ELF_MAGIC "\x7fELF"

/* PE signature */
#define PE_SIGNATURE "MZ"

/* File header info */
typedef struct {
    char *data;
    size_t len;
    int is_elf;
    int is_pe;
} FileHeaderInfo;

/* Detection result */
typedef struct {
    int detected;
    char packer[64];
    float entropy;
    int elf_magic;
    int pe_magic;
} DetectResult;

/* Calculate Shannon entropy of data */
static double calculate_entropy(const uint8_t *data, size_t len)
{
    if (len == 0) return 0.0;
    
    unsigned char freq[256] = {0};
    int i;
    
    /* Count byte frequencies */
    for (i = 0; i < (int)len; i++) {
        freq[data[i]]++;
    }
    
    /* Calculate entropy */
    double entropy = 0.0;
    double total = (double)len;
    
    for (i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / total;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

/* Check ELF header for packer indicators */
static int check_elf_packer(const uint8_t *data, size_t len)
{
    if (len < 64) return 0;
    
    /* Check for common packed ELF section names */
    const char *packed_sections[] = {
        ".upx", ".upx0", ".upx1", ".upx2", ".upx3",
        ".packer", ".packed", ".compressed", ".asm_pack",
        ".themida", ".vmprotect", ".enigma",
        NULL
    };
    
    int i, j;
    for (i = 0; packed_sections[i] != NULL; i++) {
        const char *sec = packed_sections[i];
        size_t sec_len = strlen(sec);
        
        /* Search in ELF header and first few sections */
        for (j = 0; j < len - sec_len && j < 4096; j += 16) {
            if (memcmp(&data[j], sec, sec_len) == 0) {
                return 1;
            }
        }
    }
    
    /* Check for UPX magic in header */
    if (len >= 64 && memcmp(data + 52, "UPX!", 4) == 0) {
        return 1;
    }
    
    return 0;
}

/* Check PE header for packer indicators */
static int check_pe_packer(const uint8_t *data, size_t len)
{
    if (len < 64) return 0;
    
    /* Check MZ signature */
    if (memcmp(data, "MZ", 2) != 0) return 0;
    
    /* Check for PE header offset and magic */
    if (len >= 64 && data[62] == 'P' && data[63] == 'E') {
        /* Search for packer signatures in PE headers */
        const char *pe_packer_strings[] = {
            "UPX0", "UPX1", "UPX2", "UPX3",
            ".upx", ".packer", ".packed",
            "PECompact", "ASPack", "Themida",
            "VMProtect", "Enigma",
            NULL
        };
        
        int i, j;
        for (i = 0; pe_packer_strings[i] != NULL; i++) {
            const char *str = pe_packer_strings[i];
            size_t str_len = strlen(str);
            
            /* Search in PE header area */
            for (j = 64; j < len - str_len && j < 1024; j += 8) {
                if (memcmp(&data[j], str, str_len) == 0) {
                    return 1;
                }
            }
        }
    }
    
    /* Check for UPX PE header magic */
    if (len >= 64 && data[52] == 'U' && data[53] == 'P' && 
        data[54] == 'X' && data[55] == '!') {
        return 1;
    }
    
    return 0;
}

/* Scan for known packer strings throughout file */
static int scan_packer_strings(const uint8_t *data, size_t len)
{
    int i, j;
    
    /* Search for common packer name patterns */
    const char *patterns[] = {
        "UPX", "ASPack", "PECompact", "Themida", 
        "VMProtect", "Enigma Protector", "Armadillo",
        "FSG", "Thew", "MPRESS", "PESimp",
        NULL
    };
    
    for (i = 0; patterns[i] != NULL; i++) {
        const char *pat = patterns[i];
        size_t pat_len = strlen(pat);
        
        /* Case-insensitive search */
        for (j = 0; j <= len - pat_len; j++) {
            int match = 1;
            size_t k;
            
            for (k = 0; k < pat_len && match; k++) {
                if (tolower((unsigned char)data[j + k]) != 
                    tolower((unsigned char)pat[k])) {
                    match = 0;
                }
            }
            
            if (match) return 1;
        }
    }
    
    /* Check for UPX! magic in any location */
    for (j = 0; j <= len - 4; j++) {
        if (data[j] == 'U' && data[j+1] == 'P' && 
            data[j+2] == 'X' && data[j+3] == '!') {
            return 1;
        }
    }
    
    return 0;
}

/* Detect Mach-O specific packers */
static int check_macho_packer(const uint8_t *data, size_t len)
{
    if (len < 24) return 0;
    
    /* Check for Mach-O magic */
    if ((data[0] == 'f' && data[1] == 'a' && 
         data[2] == 't' && data[3] == 'h') ||
        (data[0] == 'c' && data[1] == 'o' && 
         data[2] == 'f' && data[3] == 'f')) {
        
        /* Search for packer indicators in Mach-O */
        const char *macho_patterns[] = {
            ".upx", ".packer", ".packed",
            "UPX0", "UPX1", "UPX2", "UPX3",
            NULL
        };
        
        int i, j;
        for (i = 0; macho_patterns[i] != NULL; i++) {
            const char *pat = macho_patterns[i];
            size_t pat_len = strlen(pat);
            
            for (j = 0; j <= len - pat_len; j++) {
                if (memcmp(&data[j], pat, pat_len) == 0) {
                    return 1;
                }
            }
        }
    }
    
    return 0;
}

/* Main detection function */
static int detect_packer(const uint8_t *data, size_t len, DetectResult *result)
{
    memset(result, 0, sizeof(DetectResult));
    
    /* Calculate entropy first - quick check for compression */
    result->entropy = calculate_entropy(data, len);
    
    /* Check file type and run appropriate detectors */
    if (len >= 64 && memcmp(data, ELF_MAGIC, 4) == 0) {
        result->elf_magic = 1;
        if (check_elf_packer(data, len)) {
            result->detected = 1;
            strncpy(result->packer, "UPX/ELF", sizeof(result->packer));
            return 1;
        }
    } else if (len >= 64 && memcmp(data, PE_SIGNATURE, 2) == 0) {
        result->pe_magic = 1;
        if (check_pe_packer(data, len)) {
            result->detected = 1;
            strncpy(result->packer, "UPX/PE", sizeof(result->packer));
            return 1;
        }
    } else {
        /* Generic scan for any file type */
        if (scan_packer_strings(data, len)) {
            result->detected = 1;
            strncpy(result->packer, "Generic/String", sizeof(result->packer));
            return 1;
        }
    }
    
    /* Check Mach-O as fallback */
    if (!result->elf_magic && !result->pe_magic) {
        check_macho_packer(data, len);
    }
    
    /* High entropy might indicate packing even without magic */
    if (result->entropy > ENTROPY_THRESHOLD && result->detected == 0) {
        result->detected = 1;
        strncpy(result->packer, "HighEntropy", sizeof(result->packer));
    }
    
    return result->detected;
}

/* Open and scan a file */
static int scan_file(const char *path, DetectResult *result)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s\n", path);
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (fsize <= 0 || fsize > MAX_FILE_SIZE) {
        fclose(fp);
        return -1;
    }
    
    result->data = malloc(fsize + 1);
    if (!result->data) {
        fclose(fp);
        return -1;
    }
    
    fread(result->data, 1, fsize, fp);
    fclose(fp);
    
    /* Add null terminator for string operations */
    result->len = (size_t)fsize;
    
    return detect_packer((uint8_t*)result->data, result->len, result);
}

/* Print detection results */
static void print_result(const char *filename, DetectResult *r)
{
    printf("File: %s\n", filename ? filename : "(memory)") ;
    printf("  Detected: %s\n", r->detected ? "YES" : "NO");
    if (r->detected) {
        printf("  Packer: %s\n", r->packer);
    }
    printf("  Entropy: %.2f bits/byte\n", r->entropy);
    printf("  ELF Magic: %d, PE Magic: %d\n", r->elf_magic, r->pe_magic);
}

/* Demo/test function */
static int run_demo(void)
{
    /* Create test files in memory for demonstration */
    
    /* Test 1: Normal ELF binary (simulated header) */
    uint8_t normal_elf[64] = {
        0x7f, 'E', 'L', 'F', 2, 1, 1, 1,
        0x00, 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00,
        /* ... padding */
    };
    
    DetectResult r1;
    memset(&r1, 0, sizeof(r1));
    memcpy(r1.data, normal_elf, 64);
    r1.len = 64;
    
    int found = detect_packer((uint8_t*)r1.data, 64, &r1);
    printf("Test 1 (Normal ELF): detected=%d\n", found ? 1 : 0);
    
    /* Test 2: Simulated UPX-packed PE header */
    uint8_t upx_pe[64] = {
        'M', 'Z', 90, 3, 0, 0, 0, 0,
        0x0e, 0x1f, 0xba, 0x07, 0x00, 0x00, 0x00, 0x00,
        /* ... padding */
    };
    
    DetectResult r2;
    memset(&r2, 0, sizeof(r2));
    memcpy(r2.data, upx_pe, 64);
    r2.len = 64;
    
    found = detect_packer((uint8_t*)r2.data, 64, &r2);
    printf("Test 2 (PE Header): detected=%d\n", found ? 1 : 0);
    
    /* Test 3: High entropy data */
    uint8_t high_entropy[256];
    for (int i = 0; i < 256; i++) {
        high_entropy[i] = (uint8_t)(i * 7 + 13);
    }
    
    DetectResult r3;
    memset(&r3, 0, sizeof(r3));
    memcpy(r3.data, high_entropy, 256);
    r3.len = 256;
    
    found = detect_packer((uint8_t*)r3.data, 256, &r3);
    printf("Test 3 (High Entropy): detected=%d, entropy=%.2f\n", 
           found ? 1 : 0, r3.entropy);
    
    return 0;
}

/* Command-line interface */
static int cmd_scan(const char *path)
{
    DetectResult result;
    memset(&result, 0, sizeof(result));
    
    if (scan_file(path, &result)) {
        print_result(path, &result);
        return result.detected ? 1 : 0;
    }
    return -1;
}

/* Main entry point */
int main(int argc, char *argv[])
{
    int ret = 0;
    
    if (argc < 2) {
        /* Run demo mode */
        printf("binhunt/packer_detector: Packer Detection Module\n");
        printf("Running self-test...\n\n");
        
        ret = run_demo();
        
        printf("\nSelf-test complete.\n");
    } else {
        /* Command-line scan mode */
        for (int i = 1; i < argc && !ret; i++) {
            if (cmd_scan(argv[i])) {
                ret = 1;
            }
        }
    }
    
    return ret ? 1 : 0;
}

/* 
 * Usage: packer_detector [file1] [file2] ...
 * 
 * If no files provided, runs self-test with demo data.
 */