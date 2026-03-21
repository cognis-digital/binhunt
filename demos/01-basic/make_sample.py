"""Regenerate demos/01-basic/sample.elf (a minimal valid 64-bit ELF).

Not needed at runtime -- the sample is committed -- but kept so the demo
binary is reproducible and auditable (no opaque blobs).
"""
import os
import struct


def build_sample_elf() -> bytes:
    # Section contents: a low-entropy .text and a high-entropy .packed.
    text = b"\x90" * 64  # NOP sled, entropy ~0
    # deterministic pseudo-random high-entropy payload
    packed = bytes((i * 167 + 13) % 256 for i in range(4096))
    shstrtab = b"\x00.text\x00.packed\x00.shstrtab\x00"

    ehsize = 64
    shentsize = 64
    # layout: [ehdr][text][packed][shstrtab][section headers]
    text_off = ehsize
    packed_off = text_off + len(text)
    shstr_off = packed_off + len(packed)
    sh_off = shstr_off + len(shstrtab)
    num_sections = 4  # null, .text, .packed, .shstrtab

    e = bytearray()
    e += b"\x7fELF"
    e += bytes([2, 1, 1, 0])  # 64-bit, LE, ELF v1, SysV
    e += b"\x00" * 8
    e += struct.pack("<H", 2)        # e_type ET_EXEC
    e += struct.pack("<H", 0x3e)     # e_machine x86-64
    e += struct.pack("<I", 1)        # e_version
    e += struct.pack("<Q", 0)        # e_entry
    e += struct.pack("<Q", 0)        # e_phoff
    e += struct.pack("<Q", sh_off)   # e_shoff
    e += struct.pack("<I", 0)        # e_flags
    e += struct.pack("<H", ehsize)   # e_ehsize
    e += struct.pack("<H", 0)        # e_phentsize
    e += struct.pack("<H", 0)        # e_phnum
    e += struct.pack("<H", shentsize)
    e += struct.pack("<H", num_sections)  # e_shnum
    e += struct.pack("<H", 3)        # e_shstrndx -> .shstrtab
    assert len(e) == ehsize

    body = bytearray(text)
    body += packed
    body += shstrtab

    def shdr(name_off, sh_type, offset, size):
        return struct.pack("<IIQQQQIIQQ",
                           name_off, sh_type, 0, 0, offset, size, 0, 0, 0, 0)

    headers = bytearray()
    headers += shdr(0, 0, 0, 0)                       # null
    headers += shdr(1, 1, text_off, len(text))        # .text
    headers += shdr(7, 1, packed_off, len(packed))    # .packed
    headers += shdr(15, 3, shstr_off, len(shstrtab))  # .shstrtab

    return bytes(e) + bytes(body) + bytes(headers)


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "sample.elf")
    with open(out, "wb") as fh:
        fh.write(build_sample_elf())
    print(f"wrote {out}")
