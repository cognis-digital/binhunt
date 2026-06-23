// Go port of the binhunt core scan surface — single binary, zero deps.
//
// Mirrors the Python reference CLI (`binhunt scan <file>`):
//   - format/arch detection (PE / ELF / Mach-O)
//   - sha256 + md5 fingerprint
//   - Shannon entropy (overall)
//   - packer/obfuscator signature scan (UPX, Themida, VMProtect, ...)
//   - emits the same JSON shape: {tool, path, fmt, sha256, overall_entropy, packers, findings}
//
// Passive/offline only: reads a local file, never touches the network.
package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
)

type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

type Result struct {
	Tool           string    `json:"tool"`
	Path           string    `json:"path"`
	Size           int       `json:"size"`
	Fmt            string    `json:"fmt"`
	Arch           string    `json:"arch"`
	SHA256         string    `json:"sha256"`
	MD5            string    `json:"md5"`
	OverallEntropy float64   `json:"overall_entropy"`
	Packers        []string  `json:"packers"`
	Findings       []Finding `json:"findings"`
	MaxSeverity    string    `json:"max_severity"`
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	ent := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			ent -= p * math.Log2(p)
		}
	}
	return math.Round(ent*10000) / 10000
}

func detectFormat(d []byte) (string, string) {
	if len(d) >= 2 && d[0] == 'M' && d[1] == 'Z' {
		return "PE", "unknown"
	}
	if len(d) >= 4 && d[0] == 0x7f && d[1] == 'E' && d[2] == 'L' && d[3] == 'F' {
		arch := "unknown"
		if len(d) >= 20 {
			switch d[18] {
			case 0x3e:
				arch = "x86-64"
			case 0x03:
				arch = "x86"
			case 0xb7:
				arch = "arm64"
			case 0x28:
				arch = "arm"
			}
		}
		return "ELF", arch
	}
	if len(d) >= 4 {
		m := d[:4]
		machoLE := bytes.Equal(m, []byte{0xce, 0xfa, 0xed, 0xfe}) || bytes.Equal(m, []byte{0xcf, 0xfa, 0xed, 0xfe})
		machoBE := bytes.Equal(m, []byte{0xfe, 0xed, 0xfa, 0xce}) || bytes.Equal(m, []byte{0xfe, 0xed, 0xfa, 0xcf})
		if machoLE || machoBE {
			return "MachO", "unknown"
		}
	}
	return "unknown", "unknown"
}

var packerSigs = []struct{ sig, label string }{
	{"UPX!", "UPX"}, {"UPX0", "UPX"}, {".themida", "Themida"},
	{"VMProtect", "VMProtect"}, {"ASPack", "ASPack"},
	{"PECompact", "PECompact"}, {"MPRESS", "MPRESS"}, {"Enigma", "Enigma"},
}

func detectPackers(data []byte) []string {
	head := data
	if len(data) > 65536 {
		head = data[:65536]
	}
	var tail []byte
	if len(data) > 65536 {
		tail = data[len(data)-65536:]
	}
	set := map[string]bool{}
	for _, p := range packerSigs {
		s := []byte(p.sig)
		if bytes.Contains(head, s) || (tail != nil && bytes.Contains(tail, s)) {
			set[p.label] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var sevRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func scan(path string) (*Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fmtName, arch := detectFormat(data)
	overall := shannonEntropy(data)
	packers := detectPackers(data)

	r := &Result{
		Tool:           "binhunt",
		Path:           path,
		Size:           len(data),
		Fmt:            fmtName,
		Arch:           arch,
		SHA256:         fmt.Sprintf("%x", sha256.Sum256(data)),
		MD5:            fmt.Sprintf("%x", md5.Sum(data)),
		OverallEntropy: overall,
		Packers:        packers,
		Findings:       []Finding{},
		MaxSeverity:    "info",
	}
	for _, p := range packers {
		sev := "medium"
		if p == "Themida" || p == "VMProtect" || p == "Enigma" {
			sev = "high"
		}
		r.Findings = append(r.Findings, Finding{"PACKER", sev, "Packer/obfuscator detected: " + p})
	}
	if overall >= 7.2 && len(packers) == 0 && fmtName != "unknown" {
		r.Findings = append(r.Findings, Finding{"HIGH_ENTROPY", "medium", "High overall entropy"})
	}
	if fmtName == "unknown" {
		r.Findings = append(r.Findings, Finding{"FMT_UNKNOWN", "info", "Unrecognized binary format"})
	}
	for _, f := range r.Findings {
		if sevRank[f.Severity] > sevRank[r.MaxSeverity] {
			r.MaxSeverity = f.Severity
		}
	}
	return r, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: binhunt-go <file>")
		os.Exit(1)
	}
	r, err := scan(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(out))
	if sevRank[r.MaxSeverity] >= sevRank["medium"] {
		os.Exit(2)
	}
}
