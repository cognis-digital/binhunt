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

// PackerDetector finds packers and obfuscators in PE executables.
type PackerDetector struct {
	Path string
}

func NewPackerDetector(path string) *PackerDetector {
	return &PackerDetector{Path: path}
}

// Result holds the detection findings.
type Result struct {
	IsPE         bool
	Bitness      int // 32 or 64
	PackersFound []string
	Sections     []SectionInfo
	Score        float64
}

// SectionInfo describes a PE section found during analysis.
type SectionInfo struct {
	Name    string
	Size    uint32
	Entropy float64
}

func (d *PackerDetector) Detect() (*Result, error) {
	result := &Result{Path: d.Path}

	data, err := os.ReadFile(d.Path)
	if err != nil {
		return result, fmt.Errorf("read file: %w", err)
	}

	result.IsPE = isPE(data)
	if !result.IsPE {
		return result, nil
	}

	result.Bitness = detectBitness(data)
	result.Sections = analyzeSections(data)
	result.PackersFound = findPackers(data, result.Sections)
	result.Score = calculateScore(result)

	return result, nil
}

// isPE checks for DOS and PE headers.
func isPE(data []byte) bool {
	if len(data) < 64 {
		return false
	}

	dosMagic := binary.LittleEndian.Uint16(data[:2])
	if dosMagic != 0x5A4D {
		return false
	}

	peOffset := uint32(binary.LittleEndian.Uint16(data[60:62]))
	if peOffset == 0 || peOffset > uint32(len(data)) {
		return false
	}

	peMagic := binary.LittleEndian.Uint16(data[peOffset : peOffset+2])
	return peMagic == 0x4550
}

// detectBitness returns 32 or 64 based on optional header magic.
func detectBitness(peData []byte) int {
	peOffset := uint32(binary.LittleEndian.Uint16(peData[60:62]))
	if peOffset+2 > uint32(len(peData)) {
		return 32 // default
	}

	magic := binary.LittleEndian.Uint16(peData[peOffset : peOffset+2])
	if magic == 0x10b && len(peData) >= int(peOffset+90) {
		return 64
	}
	return 32
}

// analyzeSections extracts section headers and calculates entropy.
func analyzeSections(data []byte) []SectionInfo {
	var sections []SectionInfo

	peOffset := uint32(binary.LittleEndian.Uint16(data[60:62]))
	if peOffset+4 > uint32(len(data)) {
		return sections
	}

	numSections := binary.LittleEndian.Uint16(data[peOffset+2 : peOffset+4])
	for i := 0; i < int(numSections); i++ {
		offset := peOffset + 4 + (i * 40)
		if offset+40 > uint32(len(data)) {
			break
		}

		nameLen := binary.LittleEndian.Uint16(data[offset : offset+2])
		nameStart := offset + 2
		nameEnd := nameStart + nameLen

		nameBytes := data[nameStart:nameEnd]
		name := string(bytes.TrimRight(nameBytes, "\x00"))

		size := binary.LittleEndian.Uint32(data[offset+16 : offset+20])

		if size > 0 {
			entropy := calculateEntropy(data[offset:offset+int(size)])
			sections = append(sections, SectionInfo{
				Name:    name,
				Size:    size,
				Entropy: entropy,
			})
		}
	}

	return sections
}

// calculateEntropy computes Shannon entropy of data.
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make([]uint32, 256)
	for _, b := range data {
		freq[b]++
	}

	var entropy float64 = 0
	total := float64(len(data))

	for _, f := range freq {
		if f > 0 {
			p := f / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// findPackers scans for known packer signatures.
func findPackers(data []byte, sections []SectionInfo) []string {
	var found []string

	// UPX signature in DOS header
	if len(data) >= 64 {
		dosHeader := string(data[0:12])
		if strings.Contains(dosHeader, "UPX!") || strings.Contains(dosHeader, "UPX") {
			found = append(found, "UPX (DOS header)")
		}
	}

	// UPX section names
	for _, s := range sections {
		lowerName := strings.ToLower(s.Name)
		if lowerName == "upx0" || lowerName == "upx1" || lowerName == "upx2" ||
			lowerName == "upx3" || lowerName == "upx4" {
			found = append(found, fmt.Sprintf("UPX section: %s", s.Name))
		}
	}

	// High entropy sections (likely packed)
	for _, s := range sections {
		if s.Entropy > 7.5 && s.Size > 1024*1024 { // > 7.5 bits, > 1MB
			found = append(found, fmt.Sprintf("High-entropy section: %s (ent=%.2f)", s.Name, s.Entropy))
		}
	}

	// Themida/ASpack signatures in resources or imports
	if len(data) >= 64 {
		peOffset := uint32(binary.LittleEndian.Uint16(data[60:62]))
		if peOffset+90 <= uint32(len(data)) {
			optMagic := binary.LittleEndian.Uint16(data[peOffset : peOffset+2])
			if optMagic == 0x10b && len(data) >= int(peOffset+90) {
				// Check for Themida in resources (simplified check)
				resStart := peOffset + 90
				if resStart+4 <= uint32(len(data)) {
					resMagic := binary.LittleEndian.Uint16(data[resStart : resStart+2])
					if resMagic == 0x10b || resMagic == 0x20b { // 32/64 bit resources
						// Check for Themida resource signature
						if len(data) >= int(peOffset+98) {
							resName := string(bytes.TrimRight(data[resStart+2:resStart+12], "\x00"))
							if strings.Contains(resName, "Themida") || resName == "THEMIDA" {
								found = append(found, "Themida resource detected")
							}
						}
					}
				}
			}
		}
	}

	// ASpack/PECompact section patterns
	for _, s := range sections {
		lowerName := strings.ToLower(s.Name)
		if lowerName == "aspack" || lowerName == "pecompact" ||
			lowerName == "pccompact" || lowerName == "ascppack" {
			found = append(found, fmt.Sprintf("ASPack/PECompact section: %s", s.Name))
		}
	}

	return found
}

// calculateScore provides a confidence score (0-100).
func calculateScore(r *Result) float64 {
	score := 50.0 // base score for PE format

	if len(r.PackersFound) > 0 {
		// Add points per packer found, capped at 80
		packerPoints := min(30.0, float64(len(r.PackersFound))*10)
		score += packerPoints
	}

	// Bonus for high entropy sections
	highEntropyCount := 0
	for _, s := range r.Sections {
		if s.Entropy > 7.5 && s.Size > 1024*1024 {
			highEntropyCount++
		}
	}
	score += float64(highEntropyCount) * 2

	// Cap at 100
	return min(100.0, score)
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run packer_detector.go <binary_path>")
		os.Exit(1)
	}

	path := os.Args[1]
	detector := NewPackerDetector(path)

	result, err := detector.Detect()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== Packer Detection Report ===\n")
	fmt.Printf("File: %s\n", path)
	fmt.Printf("Format: PE%d\n", result.Bitness)
	fmt.Printf("IsPE: %t\n", result.IsPE)
	fmt.Printf("Score: %.1f/100\n", result.Score)

	if len(result.PackersFound) > 0 {
		fmt.Println("\nPackers Detected:")
		for _, p := range result.PackersFound {
			fmt.Printf("  • %s\n", p)
		}
	} else {
		fmt.Println("\nNo known packers detected.")
	}

	if len(result.Sections) > 0 {
		fmt.Println("\nTop Sections by Entropy:")
		type entPair struct{ name string; ent float64 }
		var top []entPair
		for _, s := range result.Sections {
			top = append(top, entPair{s.Name, s.Entropy})
		}

		// Sort descending by entropy
		for i := 0; i < len(top)-1; i++ {
			for j := i + 1; j < len(top); j++ {
				if top[j].ent > top[i].ent {
					top[i], top[j] = top[j], top[i]
				}
			}
		}

		fmt.Println("Rank | Name       | Entropy")
		fmt.Println("-----|------------|--------")
		for i, t := range top[:5] {
			if i < 3 {
				fmt.Printf("%4d | %-9s | %.2f\n", i+1, t.name, t.ent)
			} else if i == 3 {
				fmt.Println("     | ...        |")
			}
		}
	}

	fmt.Println("\n=== End Report ===\n")
}