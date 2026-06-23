# Ports of binhunt

The binhunt **scan** surface, ported across languages so you can drop integrity
checks into any stack or ship a single static binary. Every port mirrors the
Python reference (`binhunt scan <file>`):

- format + architecture detection (PE / ELF / Mach-O)
- `sha256` (and `md5` where the stdlib provides it) fingerprint
- overall **Shannon entropy** (bits/byte)
- **packer/obfuscator** signature scan (UPX, Themida, VMProtect, ASPack, MPRESS, Enigma, …)
- the same JSON shape: `{tool, path, size, fmt, arch, sha256, overall_entropy, packers, findings, max_severity}`
- the same **exit code** contract: `2` when the worst finding is `medium`+, `0` when clean, `1` on error

All ports are **passive/offline** — they read one local file and never touch the
network. They are byte-for-byte consistent with the Python reference on the
committed `demos/01-basic/sample.elf` fixture (same sha256, same entropy).

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../binhunt/` | `binhunt scan <file>` | `python -m pytest` |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js <file>` | `node --test ports/javascript/test.js` |
| Go | `go/` | `cd ports/go && go run . <file>` | `cd ports/go && go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- <file>` | `cd ports/rust && cargo test` |

Each port builds and is tested on every push by
[`.github/workflows/ports.yml`](../.github/workflows/ports.yml) — Node, Go, and
Rust jobs run the unit tests and a smoke scan of the demo sample.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome —
see ../CONTRIBUTING.md.
