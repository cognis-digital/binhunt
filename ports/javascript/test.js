// Smoke test for the JS port. Run: node ports/javascript/test.js
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { shannonEntropy, detectFormat, detectPackers, scan } from "./index.js";

test("entropy bounds", () => {
  assert.equal(shannonEntropy(Buffer.alloc(0)), 0.0);
  assert.equal(shannonEntropy(Buffer.alloc(1000)), 0.0);
  const all = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  assert.ok(Math.abs(shannonEntropy(all) - 8.0) < 1e-4);
});

test("format detection", () => {
  assert.equal(detectFormat(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))[0], "ELF");
  assert.equal(detectFormat(Buffer.from("MZ\x00\x00", "latin1"))[0], "PE");
  assert.equal(detectFormat(Buffer.from("garbage!"))[0], "unknown");
});

test("packer signature scan", () => {
  const blob = Buffer.concat([
    Buffer.from("MZ"), Buffer.alloc(100), Buffer.from("UPX!"), Buffer.alloc(100),
  ]);
  assert.ok(detectPackers(blob).includes("UPX"));
});

test("scan high-entropy ELF produces finding + matches sha256", () => {
  // build a minimal high-entropy buffer with ELF magic
  const body = Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 167 + 13) % 256));
  const buf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.alloc(10), Buffer.from([0x3e, 0x00]), body]);
  const dir = mkdtempSync(join(tmpdir(), "binhunt-"));
  const p = join(dir, "x.elf");
  writeFileSync(p, buf);
  const r = scan(p);
  assert.equal(r.fmt, "ELF");
  assert.equal(r.sha256.length, 64);
  assert.ok(r.findings.some((f) => f.id === "HIGH_ENTROPY"));
  assert.ok(["medium", "high", "critical"].includes(r.max_severity));
});
