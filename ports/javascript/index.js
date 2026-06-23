#!/usr/bin/env node
// JavaScript / Node port of the binhunt core scan surface.
//
// Mirrors the Python reference CLI (`binhunt scan <file>`): format/arch
// detection, sha256+md5 fingerprint, Shannon entropy, packer signature scan.
// Emits the same JSON shape. Passive/offline only — reads one local file.
import { readFileSync } from "fs";
import { createHash } from "crypto";

const PACKER_SIGS = [
  ["UPX!", "UPX"], ["UPX0", "UPX"], [".themida", "Themida"],
  ["VMProtect", "VMProtect"], ["ASPack", "ASPack"],
  ["PECompact", "PECompact"], ["MPRESS", "MPRESS"], ["Enigma", "Enigma"],
];
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function shannonEntropy(buf) {
  if (buf.length === 0) return 0.0;
  const counts = new Array(256).fill(0);
  for (const b of buf) counts[b]++;
  const n = buf.length;
  let ent = 0.0;
  for (const c of counts) {
    if (c) { const p = c / n; ent -= p * Math.log2(p); }
  }
  return Math.round(ent * 10000) / 10000;
}

export function detectFormat(buf) {
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) return ["PE", "unknown"];
  if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    const arch = { 0x3e: "x86-64", 0x03: "x86", 0xb7: "arm64", 0x28: "arm" }[buf[18]] || "unknown";
    return ["ELF", arch];
  }
  if (buf.length >= 4) {
    const m = [buf[0], buf[1], buf[2], buf[3]].join(",");
    const macho = new Set(["206,250,237,254", "207,250,237,254", "254,237,250,206", "254,237,250,207"]);
    if (macho.has(m)) return ["MachO", "unknown"];
  }
  return ["unknown", "unknown"];
}

export function detectPackers(buf) {
  const head = buf.subarray(0, Math.min(65536, buf.length));
  const tail = buf.length > 65536 ? buf.subarray(buf.length - 65536) : Buffer.alloc(0);
  const set = new Set();
  for (const [sig, label] of PACKER_SIGS) {
    const needle = Buffer.from(sig, "latin1");
    if (head.includes(needle) || (tail.length && tail.includes(needle))) set.add(label);
  }
  return [...set].sort();
}

export function scan(path) {
  const buf = readFileSync(path);
  const [fmt, arch] = detectFormat(buf);
  const overall = shannonEntropy(buf);
  const packers = detectPackers(buf);
  const findings = [];
  for (const p of packers) {
    const sev = ["Themida", "VMProtect", "Enigma"].includes(p) ? "high" : "medium";
    findings.push({ id: "PACKER", severity: sev, title: `Packer/obfuscator detected: ${p}` });
  }
  if (overall >= 7.2 && packers.length === 0 && fmt !== "unknown")
    findings.push({ id: "HIGH_ENTROPY", severity: "medium", title: "High overall entropy" });
  if (fmt === "unknown")
    findings.push({ id: "FMT_UNKNOWN", severity: "info", title: "Unrecognized binary format" });
  let maxSev = "info";
  for (const f of findings) if (SEV_RANK[f.severity] > SEV_RANK[maxSev]) maxSev = f.severity;
  return {
    tool: "binhunt", path, size: buf.length, fmt, arch,
    sha256: createHash("sha256").update(buf).digest("hex"),
    md5: createHash("md5").update(buf).digest("hex"),
    overall_entropy: overall, packers, findings, max_severity: maxSev,
  };
}

const isMain = import.meta.url === `file://${process.argv[1]}` ||
  process.argv[1]?.endsWith("index.js");
if (isMain) {
  const target = process.argv[2];
  if (!target) { console.error("usage: binhunt-js <file>"); process.exit(1); }
  try {
    const r = scan(target);
    console.log(JSON.stringify(r, null, 2));
    process.exit(SEV_RANK[r.max_severity] >= SEV_RANK.medium ? 2 : 0);
  } catch (e) { console.error(`error: ${e.message}`); process.exit(1); }
}
