import * as fs from 'fs';
import * as path from 'path';
import { createReadStream, createWriteStream } from 'stream';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

export interface BinaryInfo {
  name: string;
  size: number;
  magic: string;
  format: 'PE' | 'ELF' | 'Mach-O' | 'Unknown';
  timestamp: Date;
}

export interface HashResult {
  md5: string;
  sha256: string;
  xxh3_128?: number[]; // XXH3 hash (lower 128 bits)
}

export interface PackerSignature {
  name: string;
  confidence: 'high' | 'medium' | 'low';
  indicators: string[];
}

export interface FingerprintResult extends HashResult {
  info: BinaryInfo;
  packers?: PackerSignature[];
  entropy: number;
  headerChecksum: number;
  sectionCount: number;
}

export interface DiffResult {
  baselineHash: string;
  currentHash: string;
  isModified: boolean;
  modifiedBytes: number;
  diffPercentage: number;
  changedSections?: string[];
}

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

const HASH_ALGORITHMS = ['md5', 'sha256'] as const;
const ENTROPY_THRESHOLD_MODERATE = 7.0;
const ENTROPY_THRESHOLD_HIGH = 8.0;
const MAX_HEADER_SIZE = 4096;

// Common packer signatures (hex patterns in first 1KB)
const PACKER_SIGNATURES: Record<string, { name: string; confidence: 'high' | 'medium' | 'low'; offset: number }> = {
  // UPX compression
  'UPX0!': { name: 'UPX', confidence: 'high', offset: 0 },
  'UPX1!': { name: 'UPX', confidence: 'high', offset: 0 },
  
  // Themida packer
  'Themida': { name: 'Themida', confidence: 'medium', offset: 0 },
  
  // VMProtect
  'VMProtect': { name: 'VMProtect', confidence: 'medium', offset: 0 },
  
  // ASPack
  'ASPack': { name: 'ASPack', confidence: 'low', offset: 0 },
  
  // PECompact
  'PECompact!': { name: 'PECompact', confidence: 'high', offset: 0 },
  
  // Themida/VMProtect common header markers
  '\x4D\x5A\x90': { name: 'MZ (Standard)', confidence: 'medium', offset: 0 },
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function readHeader(buffer: Buffer, maxSize = MAX_HEADER_SIZE): string {
  const header = buffer.slice(0, Math.min(maxSize, buffer.length)).toString('hex');
  return header;
}

function calculateEntropy(data: Uint8Array): number {
  if (data.length === 0) return 0;
  
  // Frequency analysis for entropy calculation
  const freq = new Array(256).fill(0);
  for (const byte of data) {
    freq[byte]++;
  }
  
  let entropy = 0;
  const total = data.length;
  for (const count of freq) {
    if (count > 0) {
      const p = count / total;
      entropy -= p * Math.log2(p);
    }
  }
  
  return entropy;
}

function detectFormat(buffer: Buffer): 'PE' | 'ELF' | 'Mach-O' | 'Unknown' {
  // PE (Windows) - starts with MZ header
  if (buffer.length >= 2 && buffer[0] === 0x4D && buffer[1] === 0x5A) {
    return 'PE';
  }
  
  // ELF (Linux/Unix)
  if (buffer.length >= 4 && 
      ((buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) ||
       (buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x01))) {
    return 'ELF';
  }
  
  // Mach-O (macOS) - simpler check for now
  if (buffer.length >= 8 && 
      ((buffer[0] === 0xFE && buffer[1] === 0xED) || // Fat binary
       (buffer[0] === 0xCF && buffer[1] === 0xFA))) { // Thin binary
    return 'Mach-O';
  }
  
  return 'Unknown';
}

// ============================================================================
// HASHING MODULE
// ============================================================================

class HashCalculator {
  private buffers: Buffer[] = [];
  
  add(buffer: Buffer): void {
    this.buffers.push(buffer);
  }
  
  finalize(): Promise<HashResult> {
    const combined = Buffer.concat(this.buffers);
    
    return Promise.all([
      this.calculateMD5(combined),
      this.calculateSHA256(combined),
    ]);
  }
  
  private calculateMD5(data: Buffer): Promise<string> {
    // Simple MD5 implementation for portability
    const md5 = new (class {
      private state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];
      
      update(data: Buffer): void {
        const len = data.length;
        
        // Pad to 512-bit (64-byte) boundary
        let totalLen = this.state[0] + len * 8;
        if ((totalLen % 64) > 56) {
          totalLen += 64 - (totalLen % 64);
        } else {
          totalLen += 128 - (totalLen % 64);
        }
        
        // Pad with zeros
        const padded = Buffer.alloc(totalLen / 8);
        data.copy(padded, 0, 0, len);
        
        // Add length as 64-bit big-endian
        padded.writeUInt32BE(len * 8, padded.length - 4);
        padded.writeUInt32BE(0, padded.length - 8);
        
        this.processBlock(padded);
      }
      
      processBlock(block: Buffer): void {
        const S = [7, 12, 17, 22, 7, 12, 17, 22];
        const A = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];
        
        for (let i = 0; i < block.length / 4; i++) {
          A[0] = this.f(A[0], A[1], A[2], A[3], S[i % 4], block.readUInt32BE(i * 4), 1);
        }
      }
      
      f(a: number, b: number, c: number, d: number, s: number, x: number, add: number): number {
        return ((a + this.lrot(b, s) + c + (d ^ x)) | 0) + add;
      }
      
      lrot(a: number, n: number): number {
        return ((a << n) | (a >>> (32 - n))) | 0;
      }
      
      get hex(): string {
        let result = '';
        for (let i = 0; i < 4; i++) {
          result += this.state[i].toString(16).padStart(8, '0');
        }
        return result.toUpperCase();
      }
    })();
    
    md5.update(combined);
    return md5.hex;
  }
  
  private calculateSHA256(data: Buffer): Promise<string> {
    // Simple SHA-256 implementation
    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243186be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x6ff34fa5,
        0x85b1d2e5, 0x9a54ffcf, 0x0de4d26b, 0x275e2fcd, 0x4cc9d862, 0x6ca4b5bf, 0x7d840130, 0x9d2f05d2
    ];
    
    const H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b0d6ccf, 0x0b0dfa5, 0xf61e2562
    ];
    
    // Pad message
    const len = data.length * 8;
    let padded = Buffer.alloc((len / 64 + 2) * 64);
    data.copy(padded, 0);
    padded.writeUInt32BE(len - (padded.length - 1), padded.length - 4);
    
    // Process in 512-bit chunks
    for (let i = 0; i < padded.length / 64; i++) {
        const chunk = padded.slice(i * 64, i * 64 + 64);
        
        // Initialize working variables
        let a = H[0], b = H[1], c = H[2], d = H[3];
        let e = H[4], f = H[5], g = H[6], h = H[7];
        
        for (let j = 0; j < 64; j++) {
            const W = this.rotl((chunk.readUInt32BE(j * 4) ^ chunk.readUInt32BE(j * 4 + 1) << 24), j);
            
            if (j < 16) {
                a = this.ch(a, b, c, d, e, f, g, h, W, K[j]);
            } else {
                // Extend message schedule
                const S = [17, 14, 11, 8];
                let sIdx = j - 16;
                if (sIdx >= 52) sIdx -= 64;
                
                a = this.ch(a, b, c, d, e, f, g, h, W, K[j]);
            }
        }
        
        // Add compressed chunk to running total
        H[0] = (H[0] + a) | 0;
        H[1] = (H[1] + b) | 0;
        H[2] = (H[2] + c) | 0;
        H[3] = (H[3] + d) | 0;
        H[4] = (H[4] + e) | 0;
        H[5] = (H[5] + f) | 0;
        H[6] = (H[6] + g) | 0;
        H[7] = (H[7] + h) | 0;
    }
    
    // Produce final hash value
    const result = Buffer.alloc(32);
    for (let i = 0; i < 8; i++) {
        result.writeUInt32BE(H[i], i * 4);
    }
    
    return result.toString('hex');
  }
  
  private ch(a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, W: number, K: number): void {
      a = (a + ((b & c) | (~b & d)) + e + K + W) | 0;
      [a, b] = [this.rotl(a, 5), a];
      [c, d] = [this.rotl(c, 30), c];
  }
  
  private rotl(x: number, n: number): number {
    return ((x << n) | (x >>> (32 - n))) | 0;
  }
}

// ============================================================================
// HEADER ANALYSIS MODULE
// ============================================================================

class HeaderAnalyzer {
  static analyze(buffer: Buffer): BinaryInfo & { checksum: number, sections: string[] } {
    const info: BinaryInfo = {
      name: path.basename(buffer),
      size: buffer.length,
      magic: readHeader(buffer).slice(0, 64),
      format: detectFormat(buffer),
      timestamp: new Date(),
    };
    
    // Calculate header checksum (simple XOR of first N bytes)
    let checksum = 0;
    const checkSize = Math.min(256, buffer.length);
    for (let i = 0; i < checkSize; i++) {
      checksum ^= buffer[i];
    }
    
    // Extract section names from PE header if applicable
    const sections: string[] = [];
    if (info.format === 'PE' && buffer.length >= 64) {
      // PE header offset is at 0x3C
      let peOffset = buffer.readUInt16LE(60);
      
      if (peOffset > 0 && peOffset < buffer.length - 256) {
        const peHeader = buffer.slice(peOffset, peOffset + 256);
        
        // Number of sections is at offset 0x3E within PE header
        let numSections = peHeader.readUInt16LE(48);
        if (numSections > 0 && peOffset + 64 * numSections < buffer.length) {
          for (let i = 0; i < numSections; i++) {
            const sectionName = peHeader.slice(64 * i, 64 * i + 8).toString('utf-8').trim();
            if (sectionName && sectionName !== '\x00\x00\x00\x00\x00\x00') {
              sections.push(sectionName);
            }
          }
        }
      }
    } else if (info.format === 'ELF' && buffer.length >= 64) {
      // ELF section headers are at offset 0x38
      let shOffset = buffer.readUInt32LE(40);
      
      if (shOffset > 0 && shOffset < buffer.length - 128) {
        const elfHeader = buffer.slice(shOffset, shOffset + 128);
        
        // Number of section headers is at offset 0x1A within ELF header
        let numSh = buffer.readUInt16LE(shOffset + 42);
        
        if (numSh > 0 && shOffset + 64 * numSh < buffer.length) {
          for (let i = 0; i < numSh; i++) {
            const sectionName = elfHeader.slice(64 * i, 64 * i + 16).toString('utf-8').trim();
            if (sectionName && sectionName !== '\x00\x00\x00\x00