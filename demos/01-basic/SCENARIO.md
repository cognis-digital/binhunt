# Demo 01 - Basic scan + tamper detection

This demo uses a tiny synthetic **ELF** binary (`sample.elf`) that contains a
valid ELF header, a section header table with two named sections, and a
high-entropy `.packed` section.

The file `sample.elf` is committed as part of the repo. (It is a hand-built,
minimal but structurally valid 64-bit little-endian ELF for x86-64 -- not a
real program, but enough for BINHUNT's parser to walk its section table.)

## What it shows

1. **scan** -- BINHUNT detects the format (`ELF`, `x86-64`), computes the
   sha256 / md5 / fuzzy fingerprint, parses the section table, and flags the
   high-entropy `.packed` section.

   ```
   binhunt scan demos/01-basic/sample.elf
   ```

   Expected: format `ELF (x86-64)`, a `SECTION_ENTROPY` finding for `.packed`,
   and a non-zero exit code (2) because a medium-severity finding fired.

2. **baseline + diff** -- record the file as known-good, then prove a modified
   copy is detected.

   ```
   binhunt baseline demos/01-basic/sample.elf -o /tmp/base.json
   binhunt diff demos/01-basic/sample.elf --baseline /tmp/base.json
   ```

   Expected: the unmodified file reports `MATCH` (`info`, exit 0). If even one
   byte changes, `diff` reports `HASH_MISMATCH` (`critical`, exit 2) -- this is
   the trojanized-client detection in action.

## JSON / CI usage

```
binhunt scan demos/01-basic/sample.elf --format json | jq .max_severity
```

Exit code is `2` whenever a medium+ finding fires, so it can gate CI.
