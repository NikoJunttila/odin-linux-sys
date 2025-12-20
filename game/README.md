# Compiling Odin to 32-bit on Linux

This document explains how to compile an Odin program as a 32-bit (i386) executable on Linux.

## Command

```bash
odin build . -target:linux_i386 -extra-linker-flags:"-m32" -out:main32
```

## Flags Explained

| Flag | Description |
|------|-------------|
| `-target:linux_i386` | Compile for 32-bit Linux (i386 architecture) |
| `-extra-linker-flags:"-m32"` | Pass `-m32` to the linker to produce a 32-bit binary |
| `-out:main32` | Output file name |

## Verification

Use `readelf` to confirm the binary is 32-bit:

```bash
readelf -h main32
```

Expected output should show:
- **Class:** `ELF32`
- **Machine:** `Intel 80386`

## Notes

- The `-extra-linker-flags:"-m32"` is required because the default linker targets 64-bit
- You may need 32-bit libraries installed (e.g., `libc6-dev-i386` on Debian/Ubuntu)


┌─────────────────────────────────────┐
│      Your Ryzen 5 3600 (AMD64)      │
├─────────────────────────────────────┤
│  Can run:                           │
│  ✓ 64-bit (x86-64) programs         │
│  ✓ 32-bit (x86/i386) programs       │
│  ✗ ARM programs (different arch)    │
└─────────────────────────────────────┘