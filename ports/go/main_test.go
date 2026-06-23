package main

import (
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	if shannonEntropy(nil) != 0.0 {
		t.Fatal("empty should be 0")
	}
	if shannonEntropy(make([]byte, 1000)) != 0.0 {
		t.Fatal("all-zero should be 0")
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if math.Abs(shannonEntropy(all)-8.0) > 1e-4 {
		t.Fatalf("uniform should be ~8.0, got %v", shannonEntropy(all))
	}
}

func TestDetectFormat(t *testing.T) {
	if f, _ := detectFormat([]byte{0x7f, 'E', 'L', 'F'}); f != "ELF" {
		t.Fatalf("expected ELF, got %s", f)
	}
	if f, _ := detectFormat([]byte("MZ\x00\x00")); f != "PE" {
		t.Fatalf("expected PE, got %s", f)
	}
	if f, _ := detectFormat([]byte("garbage!")); f != "unknown" {
		t.Fatalf("expected unknown, got %s", f)
	}
}

func TestDetectPackers(t *testing.T) {
	blob := append([]byte("MZ"), make([]byte, 100)...)
	blob = append(blob, []byte("UPX!")...)
	found := detectPackers(blob)
	ok := false
	for _, p := range found {
		if p == "UPX" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("expected UPX, got %v", found)
	}
}
