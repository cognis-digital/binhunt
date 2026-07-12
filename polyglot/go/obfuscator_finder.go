package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Constants for PE header magic numbers
const (
	PE32_MAGIC   = 0x010b
	PE64_MAGIC   = 0x020b
	UPX_MAGIC    = []byte{0x50, 0x55, 0x2a, 0x4d} // "UPX!"
	THEMIDA_SIG  = []byte{0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65} // "signature"
	VMPROTECT_SIG = []byte{0x56, 0x4d, 0x50, 0x52, 0x4f, 0x54, 0x45, 0x43, 0x54} // "VMProtect"
	ENIGMA_SIG   = []byte{0x45, 0x6e, 0x69, 0x67, 0x6d, 0x61, 0x2a, 0x30, 0x30} // "Enigma*"
	ASPACK_SIG   = []byte{0x41, 0x53, 0x50, 0x41, 0x43, 0x4b} // "ASPACK"
)

// Known packer signatures and their metadata
type PackerInfo struct {
	Name        string
	Magic       []byte
	Entropy     float64
	Description string
}

var knownPackers = []PackerInfo{
	{Name: "UPX", Magic: UPX_MAGIC, Description: "Ultimate Packer for eXecutables"},
	{Name: "Themida", Magic: THEMIDA_SIG, Description: "Anti-debug protection packer"},
	{Name: "VMProtect", Magic: VMPROTECT_SIG, Description: "Virtual machine based protector"},
	{Name: "Enigma Protector", Magic: ENIGMA_SIG, Description: "Code obfuscation tool"},
	{Name: "ASPack", Magic: ASPACK_SIG, Description: "Small PE executable packer"},
}

// ScanResult holds the analysis output for a single binary
type ScanResult struct {
	Path         string
	Size         int64
	IsPE32       bool
	IsPE64       bool
	PackersFound []string
	Suspicious   bool
	Entropy      float64
}

// PEHeader holds parsed PE header information
type PEHeader struct {
	Magic    uint16
	Subsystem uint16
	NumSections uint32
}

// SectionInfo represents a PE section for entropy analysis
type SectionInfo struct {
	Name  string
	Size  int64
	Data  []byte
}

// findPEMagic checks if the file is a valid PE executable and returns header info
func findPEMagic(data []byte) (*PEHeader, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("file too small to be PE")
	}

	magic := binary.LittleEndian.Uint16(data[0x3e:])
	
	header := &PEHeader{
		Magic:    magic,
		Subsystem: binary.LittleEndian.Uint16(data[0x4c]),
		NumSections: binary.LittleEndian.Uint32(data[0x5a]),
	}

	if header.Magic == PE32_MAGIC || header.Magic == PE64_MAGIC {
		return header, nil
	}
	
	return nil, fmt.Errorf("not a valid PE file (magic: 0x%x)", header.Magic)
}

// extractSections extracts all sections from PE data for entropy analysis
func extractSections(data []byte, peHeader *PEHeader) ([]SectionInfo, error) {
	var sections []SectionInfo
	
	if len(data) < 64+peHeader.NumSections*40 {
		return nil, fmt.Errorf("incomplete PE header")
	}

	for i := uint32(0); i < peHeader.NumSections; i++ {
		nameOffset := 64 + (i * 40)
		
		if nameOffset+8 > len(data) {
			break
		}
		
		nameLen := int(data[nameOffset])
		if nameLen == 0 || nameLen > 32 {
			continue
		}

		nameStart := nameOffset + 1
		nameEnd := nameStart + nameLen
		
		var name string
		if nameEnd <= len(data) {
			name = string(data[nameStart:nameEnd])
		} else {
			break
		}

		sizeOffset := nameEnd + 24 // Size field offset from section header start
		if sizeOffset+8 > len(data) {
			continue
		}
		
		var size int64
		if peHeader.Magic == PE32_MAGIC {
			size = binary.LittleEndian.Uint32(data[sizeOffset:])
		} else {
			size = int64(binary.LittleEndian.Uint32(data[sizeOffset:])) * 0x100000000 + 
			      int64(binary.LittleEndian.Uint32(data[sizeOffset+4:]))
		}

		if size > 0 && name != "" {
			sections = append(sections, SectionInfo{
				Name: name,
				Size: size,
			})
		}
	}

	return sections, nil
}

// calculateEntropy calculates Shannon entropy of byte data
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := make(map[byte]uint32)
	for _, b := range data {
		freq[b]++
	}

	var entropy float64
	total := float64(len(data))

	for count := range freq {
		p := float64(count) / total
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// detectPackers scans for known packer signatures and high-entropy sections
func detectPackers(path string, data []byte) ([]string, float64, error) {
	var foundPackers []string
	
	// Check magic numbers
	for _, p := range knownPackers {
		if len(data) >= 8 && bytes.Equal(data[:len(p.Magic)], p.Magic) {
			foundPackers = append(foundPackers, p.Name)
		}
	}

	// Check for UPX in header (alternative signature)
	upxOffset := 0x3e // PE magic offset
	if len(data) >= upxOffset+4 {
		magic := binary.LittleEndian.Uint32(data[upxOffset:])
		if magic == 0x50552a4d || magic == 0x552a4d50 { // UPX or reversed
			foundPackers = append(foundPackers, "UPX")
		}
	}

	// Analyze sections for high entropy (common in packed files)
	if len(data) > 64 {
		peHeader, err := findPEMagic(data)
		if err == nil {
			sections, _ := extractSections(data, peHeader)
			
			for _, section := range sections {
				if section.Size < 1024 || section.Size > 5*1024*1024 {
					continue
				}

				// Extract raw data from PE header (simplified - just use name as proxy)
				nameData := []byte(section.Name)
				sectionEntropy := calculateEntropy(nameData)
				
				if sectionEntropy > 7.5 { // High entropy threshold
					foundPackers = append(foundPackers, fmt.Sprintf("High-entropy section: %s", section.Name))
				}
			}
		}
	}

	// Calculate overall file entropy as additional signal
	fileEntropy := calculateEntropy(data)
	
	return foundPackers, fileEntropy, nil
}

// isSuspicious determines if a binary shows signs of obfuscation
func isSuspicious(packers []string, entropy float64, peHeader *PEHeader) bool {
	if len(packers) > 0 {
		return true
	}

	if peHeader != nil && peHeader.Magic == PE32_MAGIC {
		// PE32 with high overall entropy is suspicious
		if entropy > 7.8 {
			return true
		}
	}

	return false
}

// scanFile performs the complete analysis on a file path
func scanFile(path string) (*ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	result := &ScanResult{
		Path:  filepath.Base(path),
		Size:  int64(len(data)),
	}

	// Parse PE header if applicable
	var peHeader *PEHeader
	if len(data) >= 64 {
		peHeader, err = findPEMagic(data)
		if err == nil {
			result.IsPE32 = (peHeader.Magic == PE32_MAGIC)
			result.IsPE64 = (peHeader.Magic == PE64_MAGIC)
		}
	}

	// Detect packers and calculate entropy
	packers, entropy, err := detectPackers(path, data)
	if err != nil {
		return result, fmt.Errorf("detection failed: %w", err)
	}

	result.PackersFound = packers
	result.Entropy = entropy
	result.Suspicious = isSuspicious(packers, entropy, peHeader)

	return result, nil
}

// formatResult creates a human-readable report
func formatResult(result *ScanResult) string {
	var buf strings.Builder
	
	buf.WriteString(fmt.Sprintf("File: %s\n", result.Path))
	buf.WriteString(fmt.Sprintf("Size: %d bytes\n", result.Size))
	
	if result.IsPE32 || result.IsPE64 {
		buf.WriteString(fmt.Sprintf("Format: PE%s\n", 
			map[bool]string{true: "32", false: "64"}[result.IsPE64]))
	}

	if len(result.PackersFound) > 0 {
		buf.WriteString(fmt.Sprintf("Packers/Obfuscators detected:\n"))
		for _, p := range result.PackersFound {
			buf.WriteString(fmt.Sprintf("  - %s\n", p))
		}
	} else {
		buf.WriteString("Packers: None detected\n")
	}

	if result.Suspicious {
		buf.WriteString("Status: SUSPICIOUS\n")
	} else {
		buf.WriteString("Status: NORMAL\n")
	}

	buf.WriteString(fmt.Sprintf("Overall Entropy: %.2f bits/byte\n", result.Entropy))

	return buf.String()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: binhunt scan [file1] [file2] ...")
		fmt.Println("\nScanning for packers and obfuscators in PE executables.")
		os.Exit(0)
	}

	var totalSuspicious int
	for _, path := range os.Args[1:] {
		result, err := scanFile(path)
		if err != nil {
			fmt.Printf("Error scanning %s: %v\n", path, err)
			continue
		}

		report := formatResult(result)
		fmt.Println(report)
		
		if result.Suspicious {
			totalSuspicious++
		}
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Total files scanned: %d\n", len(os.Args)-1)
	fmt.Printf("Suspicious files: %d\n", totalSuspicious)
}