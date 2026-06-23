// Rust port of the binhunt core scan surface — fast, single binary, zero deps.
//
// Mirrors the Python reference CLI (`binhunt scan <file>`): format/arch
// detection, sha256 fingerprint, Shannon entropy, packer signature scan.
// Emits the same JSON shape. Passive/offline only — reads one local file.
use std::{env, fs, process};

// ---- minimal SHA-256 (FIPS 180-4), stdlib only -------------------------
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e;
            e = d.wrapping_add(t1);
            d = c; c = b; b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|x| format!("{:08x}", x)).collect()
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut ent = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            ent -= p * p.log2();
        }
    }
    (ent * 10000.0).round() / 10000.0
}

fn detect_format(d: &[u8]) -> (&'static str, &'static str) {
    if d.len() >= 2 && d[0] == 0x4d && d[1] == 0x5a {
        return ("PE", "unknown");
    }
    if d.len() >= 4 && d[0] == 0x7f && &d[1..4] == b"ELF" {
        let arch = if d.len() >= 20 {
            match d[18] {
                0x3e => "x86-64",
                0x03 => "x86",
                0xb7 => "arm64",
                0x28 => "arm",
                _ => "unknown",
            }
        } else {
            "unknown"
        };
        return ("ELF", arch);
    }
    if d.len() >= 4 {
        let m = &d[0..4];
        let macho = [
            [0xce, 0xfa, 0xed, 0xfe], [0xcf, 0xfa, 0xed, 0xfe],
            [0xfe, 0xed, 0xfa, 0xce], [0xfe, 0xed, 0xfa, 0xcf],
        ];
        if macho.iter().any(|x| x == m) {
            return ("MachO", "unknown");
        }
    }
    ("unknown", "unknown")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn detect_packers(data: &[u8]) -> Vec<&'static str> {
    let sigs: [(&[u8], &str); 8] = [
        (b"UPX!", "UPX"), (b"UPX0", "UPX"), (b".themida", "Themida"),
        (b"VMProtect", "VMProtect"), (b"ASPack", "ASPack"),
        (b"PECompact", "PECompact"), (b"MPRESS", "MPRESS"), (b"Enigma", "Enigma"),
    ];
    let head = &data[..data.len().min(65536)];
    let tail: &[u8] = if data.len() > 65536 { &data[data.len() - 65536..] } else { &[] };
    let mut out: Vec<&'static str> = Vec::new();
    for (sig, label) in sigs.iter() {
        if (contains(head, sig) || contains(tail, sig)) && !out.contains(label) {
            out.push(label);
        }
    }
    out.sort();
    out
}

fn sev_rank(s: &str) -> i32 {
    match s {
        "info" => 0, "low" => 1, "medium" => 2, "high" => 3, "critical" => 4, _ => 0,
    }
}

fn main() {
    let target = match env::args().nth(1) {
        Some(t) => t,
        None => {
            eprintln!("usage: binhunt-rs <file>");
            process::exit(1);
        }
    };
    let data = match fs::read(&target) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    };
    let (fmt, arch) = detect_format(&data);
    let overall = shannon_entropy(&data);
    let packers = detect_packers(&data);
    let sha = sha256_hex(&data);

    let mut findings: Vec<(String, String, String)> = Vec::new();
    for p in &packers {
        let sev = if *p == "Themida" || *p == "VMProtect" || *p == "Enigma" {
            "high"
        } else {
            "medium"
        };
        findings.push((
            "PACKER".into(),
            sev.into(),
            format!("Packer/obfuscator detected: {}", p),
        ));
    }
    if overall >= 7.2 && packers.is_empty() && fmt != "unknown" {
        findings.push(("HIGH_ENTROPY".into(), "medium".into(), "High overall entropy".into()));
    }
    if fmt == "unknown" {
        findings.push(("FMT_UNKNOWN".into(), "info".into(), "Unrecognized binary format".into()));
    }
    let mut max_sev = "info";
    for (_, s, _) in &findings {
        if sev_rank(s) > sev_rank(max_sev) {
            max_sev = match s.as_str() {
                "low" => "low", "medium" => "medium", "high" => "high",
                "critical" => "critical", _ => "info",
            };
        }
    }

    let pj: Vec<String> = packers.iter().map(|p| format!("\"{}\"", p)).collect();
    let fj: Vec<String> = findings
        .iter()
        .map(|(id, sev, title)| {
            format!(
                "{{\"id\":\"{}\",\"severity\":\"{}\",\"title\":\"{}\"}}",
                id, sev, title
            )
        })
        .collect();
    println!(
        "{{\"tool\":\"binhunt\",\"path\":\"{}\",\"size\":{},\"fmt\":\"{}\",\"arch\":\"{}\",\"sha256\":\"{}\",\"overall_entropy\":{},\"packers\":[{}],\"findings\":[{}],\"max_severity\":\"{}\"}}",
        target.replace('\\', "/"),
        data.len(),
        fmt,
        arch,
        sha,
        overall,
        pj.join(","),
        fj.join(","),
        max_sev
    );
    if sev_rank(max_sev) >= sev_rank("medium") {
        process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // SHA-256("abc")
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // SHA-256("")
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(&[0u8; 1000]), 0.0);
        let all: Vec<u8> = (0..=255u16).map(|x| x as u8).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-4);
    }

    #[test]
    fn format_detection() {
        assert_eq!(detect_format(&[0x7f, b'E', b'L', b'F']).0, "ELF");
        assert_eq!(detect_format(b"MZ\x00\x00").0, "PE");
        assert_eq!(detect_format(b"garbage!").0, "unknown");
    }

    #[test]
    fn packer_scan() {
        let mut blob = b"MZ".to_vec();
        blob.extend_from_slice(&[0u8; 100]);
        blob.extend_from_slice(b"UPX!");
        assert!(detect_packers(&blob).contains(&"UPX"));
    }
}
