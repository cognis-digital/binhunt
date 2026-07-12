#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <time.h>

#define MAX_SECTIONS 256
#define MAX_SYMBOLS 4096
#define MAX_STRINGS 8192
#define HASH_SIZE 32

/* Fingerprint structure */
typedef struct {
    uint64_t entry_point;
    uint64_t load_bias;
    uint64_t total_size;
    uint64_t section_count;
    uint64_t symbol_count;
    uint64_t string_count;
    uint32_t e_machine;
    uint16_t e_type;
    uint8_t  e_version;
    char     entry_name[64];
    char     build_id[HASH_SIZE * 2 + 1];
    uint64_t hash_elfid;
    uint64_t hash_sections;
    uint64_t hash_symbols;
    uint64_t hash_strings;
} Fingerprint_t;

/* Section metadata */
typedef struct {
    char name[64];
    uint64_t offset;
    uint64_t size;
    uint32_t flags;
    uint8_t  type;
} SectionInfo;

/* Symbol info (minimal) */
typedef struct {
    char name[128];
    uint64_t value;
    uint8_t  section_index;
} SymbolInfo;

/* String table entry */
typedef struct {
    char str[MAX_STRINGS * 32 + 1];
} StringEntry;

/* ELF ID hash (from binutils) */
static uint64_t elfid_hash(const Elf64_Ehdr *ehdr, const void *data, size_t len) {
    uint64_t h = 0x3f7a5e1d2b9c8a7fULL;
    for (size_t i = 0; i < len && i < sizeof(Elf64_Ehdr); i++) {
        h ^= ((uint64_t)data[i] << (i % 64)) | (h >> 1);
        h *= 0x85ebca6bUL;
    }
    return h;
}

/* Compute SHA-256-like hash for sections */
static uint64_t section_hash(const SectionInfo *sections, size_t count) {
    uint64_t h = 14695981039346656ULL;
    for (size_t i = 0; i < count; i++) {
        const char *name = sections[i].name;
        while (*name) {
            h ^= ((uint64_t)*name << (i % 8)) | (h >> 7);
            name++;
            i += 2;
        }
    }
    return h;
}

/* Compute hash for symbols */
static uint64_t symbol_hash(const SymbolInfo *syms, size_t count) {
    uint64_t h = 0x9e3779b97f4a7c15ULL;
    for (size_t i = 0; i < count; i++) {
        const char *name = syms[i].name;
        while (*name) {
            h ^= ((uint64_t)*name << (i % 8)) | (h >> 7);
            name++;
            i += 2;
        }
    }
    return h;
}

/* Compute hash for strings */
static uint64_t string_hash(const char *strings, size_t count) {
    uint64_t h = 0xdeadbeefULL;
    for (size_t i = 0; i < count && i < MAX_STRINGS; i++) {
        const char *str = strings + (i * 32);
        while (*str) {
            h ^= ((uint64_t)*str << (i % 8)) | (h >> 7);
            str++;
            i += 2;
        }
    }
    return h;
}

/* Build ID extraction */
static int extract_build_id(const char *filename, char *buf, size_t bufsize) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) return -1;
    
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) goto cleanup;
    
    /* Check for .note.gnu.build-id */
    const char *note_name = ".note.gnu.build-id";
    size_t note_len = strlen(note_name);
    uint64_t build_id_offset = 0;
    
    if (ehdr.e_shoff == 0 || ehdr.e_shentsize == 0) {
        cleanup:
        close(fd);
        return -1;
    }
    
    /* Parse section headers */
    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(ehdr.e_phoff + ehdr.e_phentsize * ehdr.e_phnum);
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (memcmp(shdrs[i].sh_name, note_name, note_len) == 0) {
            build_id_offset = shdrs[i].sh_offset + sizeof(Elf64_Shdr);
            break;
        }
    }
    
    close(fd);
    
    if (build_id_offset > 0 && build_id_offset < bufsize) {
        memcpy(buf, filename + build_id_offset, MIN(sizeof(build_id), bufsize - 1));
        buf[sizeof(build_id)] = '\0';
        return 1;
    }
    
    return 0;
}

/* Parse ELF headers and extract metadata */
static int parse_elf(const char *filename, Fingerprint_t *fp) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    
    /* Read ELF header */
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) goto cleanup;
    
    fp->e_machine = ehdr.e_machine;
    fp->e_type = ehdr.e_type;
    fp->e_version = ehdr.e_version;
    
    /* Check for 64-bit ELF */
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Warning: Not a 64-bit ELF\n");
    }
    
    /* Read program headers to find entry point */
    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(ehdr.e_phoff + ehdr.e_phentsize * ehdr.e_phnum);
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            fp->load_bias = phdrs[i].p_offset;
            break;
        }
    }
    
    /* Read section headers */
    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(ehdr.e_shoff + ehdr.e_shentsize * ehdr.e_shnum);
    fp->section_count = 0;
    for (int i = 0; i < ehdr.e_shnum && fp->section_count < MAX_SECTIONS; i++) {
        if (shdrs[i].sh_name == SHN_UNDEF) continue;
        
        const char *name_ptr = shdr_name(shdrs, i);
        strncpy(fp->entry_name, name_ptr, sizeof(fp->entry_name) - 1);
        
        fp->sections[fp->section_count].offset = shdrs[i].sh_offset;
        fp->sections[fp->section_count].size = shdrs[i].sh_size;
        fp->sections[fp->section_count].type = shdrs[i].sh_type;
        fp->sections[fp->section_count].flags = shdrs[i].sh_flags;
        
        /* Get section name */
        const char *name = shdr_name(shdrs, i);
        strncpy(fp->entry_name, name, sizeof(fp->entry_name) - 1);
        
        fp->section_count++;
    }
    
    /* Read dynamic section for symbols if present */
    uint64_t sym_offset = 0;
    uint32_t sym_count = 0;
    
    for (int i = 0; i < ehdr.e_phnum && !sym_offset; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            const Elf64_Dyn *dyn = (const Elf64_Dyn *)(ehdr.e_shoff + shdrs[ET_DYN].sh_offset);
            for (int j = 0; dyn[j].d_tag != DT_NULL && sym_count < MAX_SYMBOLS; j++) {
                if (dyn[j].d_tag == DT_SYMTAB) {
                    const Elf64_Shdr *sym_shdr = shdrs + dyn[j].d_un.d_ptr;
                    sym_offset = sym_shdr->sh_offset;
                    sym_count = sym_shdr->sh_size / sizeof(Elf64_Sym);
                } else if (dyn[j].d_tag == DT_SYMENT) {
                    break;
                }
            }
        }
    }
    
    fp->symbol_count = sym_count;
    
    /* Read string tables */
    uint64_t strtab_offset = 0;
    for (int i = 0; i < ehdr.e_shnum && !strtab_offset; i++) {
        if (shdrs[i].sh_type == SHT_STRTAB) {
            strtab_offset = shdrs[i].sh_offset;
            break;
        }
    }
    
    fp->string_count = 0;
    if (strtab_offset > 0) {
        const char *strtab = filename + strtab_offset;
        size_t total_strings = 0;
        
        while (*strtab && total_strings < MAX_STRINGS) {
            strncpy(fp->strings[fp->string_count].str, strtab, sizeof(fp->strings[fp->string_count].str) - 1);
            fp->string_count++;
            strtab += strlen(strtab) + 1;
        }
    }
    
cleanup:
    close(fd);
    
    /* Compute hashes */
    fp->hash_elfid = elfid_hash(&ehdr, filename, ehdr.e_ehsize);
    fp->hash_sections = section_hash(fp->sections, fp->section_count);
    fp->hash_symbols = symbol_hash(NULL, 0);
    fp->hash_strings = string_hash(strtab_offset > 0 ? (const char*)filename + strtab_offset : "", 
                                   strtab_offset > 0 ? 1 : 0);
    
    return 0;
}

/* Get section name from ELF */
static const char *shdr_name(const Elf64_Shdr *shdrs, int idx) {
    if (idx < 0 || idx >= MAX_SECTIONS) return "";
    const char *name = filename + shdrs[idx].sh_offset;
    return name ? name : "";
}

/* Compare two fingerprints */
static int compare_fingerprints(const Fingerprint_t *fp1, const Fingerprint_t *fp2) {
    if (fp1->e_machine != fp2->e_machine) return 0;
    if (fp1->e_type != fp2->e_type) return 0;
    if (fp1->load_bias != fp2->load_bias) return 0;
    
    /* Compare hashes */
    uint64_t combined = fp1->hash_elfid ^ fp1->hash_sections ^ 
                       fp1->hash_symbols ^ fp1->hash_strings;
    uint64_t other_combined = fp2->hash_elfid ^ fp2->hash_sections ^ 
                            fp2->hash_symbols ^ fp2->hash_strings;
    
    return (combined == other_combined) ? 1 : 0;
}

/* Print fingerprint details */
static void print_fingerprint(const Fingerprint_t *fp, const char *filename) {
    printf("=== Binary Fingerprint: %s ===\n", filename);
    printf("Machine:   0x%x\n", fp->e_machine);
    printf("Type:      0x%x\n", fp->e_type);
    printf("Entry:     0x%lx (bias 0x%lx)\n", 
           fp->entry_point, fp->load_bias);
    printf("Size:      %lu bytes\n", fp->total_size);
    printf("Sections:  %zu\n", fp->section_count);
    printf("Symbols:   %zu\n", fp->symbol_count);
    printf("Strings:   %zu\n", fp->string_count);
    
    if (fp->build_id[0]) {
        printf("Build ID:  [%s]\n", fp->build_id);
    }
    
    printf("\nHashes:\n");
    printf("  ELFID:       0x%lx\n", fp->hash_elfid);
    printf("  Sections:     0x%lx\n", fp->hash_sections);
    printf("  Symbols:      0x%lx\n", fp->hash_symbols);
    printf("  Strings:      0x%lx\n", fp->hash_strings);
}

/* Detect common packer signatures */
static int detect_packer(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) return -1;
    
    const size_t buf_size = 65536;
    unsigned char *buf = malloc(buf_size);
    if (!buf) goto cleanup;
    
    ssize_t nread = read(fd, buf, buf_size);
    if (nread < 0) {
        perror("read");
        free(buf);
        cleanup:
        close(fd);
        return -1;
    }
    
    /* Check for common packer headers */
    const char *signatures[] = {
        "UPX!",       /* UPX */
        "PECompact!", /* PECompact */
        "ASPack",     /* ASPack */
        "Themida",    /* Themida */
        "VMProtect",  /* VMProtect */
        "Enigma",     /* Enigma Protector */
        "Armadillo",  /* Armadillo */
        "Themis",     /* Themis */
        "Spectre",    /* Spectre */
        "Dolphin",    /* Dolphin */
        NULL
    };
    
    int found = 0;
    for (int i = 0; signatures[i]; i++) {
        if (strstr((char*)buf, signatures[i])) {
            printf("Packer detected: %s\n", signatures[i]);
            found = 1;
        }
    }
    
    free(buf);
    close(fd);
    return found;
}

/* Main entry point */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary> [baseline]\n", argv[0]);
        fprintf(stderr, "\nFingerprints the binary and compares against optional baseline.\n");
        return 1;
    }
    
    const char *filename = argv[1];
    const char *baseline = argc > 2 ? argv[2] : NULL;
    
    /* Parse fingerprint */
    Fingerprint_t fp;
    if (parse_elf(filename, &fp) < 0) {
        fprintf(stderr, "Error parsing ELF: %s\n", filename);
        return 1;
    }
    
    printf("Parsed ELF successfully.\n");
    print_fingerprint(&fp, filename);
    
    /* Detect packers */
    if (detect_packer(filename)) {
        printf("\nPacker signatures found!\n");
    } else {
        printf("\nNo common packer signatures detected.\n");
    }
    
    /* Compare against baseline if provided */
    if (baseline) {
        Fingerprint_t fp_baseline;
        if (parse_elf(baseline, &fp_baseline) < 0) {
            fprintf(stderr, "Error parsing baseline: %s\n", baseline);
            return 1;
        }
        
        printf("\n=== Baseline Comparison ===\n");
        int match = compare_fingerprints(&fp, &fp_baseline);
        
        if (match) {
            printf("MATCH: Fingerprints are identical.\n");
            return 0;
        } else {
            printf("DIFFER: Fingerprints have changed since baseline.\n");
            
            /* Show differences */
            printf("\nDifferences found:\n");
            if (fp.e_machine != fp_baseline.e_machine)
                printf("  - Machine type changed\n");
            if (fp.load_bias != fp_baseline.load_bias)
                printf("  - Load bias changed\n");
            
            uint64_t combined = fp.hash_elfid ^ fp.hash_sections ^ 
                             fp.hash_symbols ^ fp.hash_strings;
            uint64_t baseline_combined