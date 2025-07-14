# crypt.frnki v1.0.0 - USB Portable Edition

**Secure file encryption tool with all critical security vulnerabilities fixed.** 🔒

## Quick Start

### Linux
```bash
chmod +x crypt.frnki
./crypt.frnki
```

### Windows
```cmd
crypt.frnki.exe
```

**No installation required.** Bundled dependencies ensure offline, portable operation.

## Repository Contents

- `crypt_frnki_standalone.py` - Source code (~24KB)
- `standalone.spec` - PyInstaller build config
- `favicon.ico` / `favicon.png` - Icons
- `README.md` - Documentation
- `LICENSE` - MIT License

Pre-built executables available in GitHub Releases:
- `crypt.frnki` - Linux (~26MB)
- `crypt.frnki.exe` - Windows (~26MB)

## Security Features

✅ **Vulnerabilities Fixed:**
- Random per-file salts
- Path traversal protection
- Input validation
- Secure memory handling
- Atomic operations
- Generic error messages

✅ **Cryptography:**
- ChaCha20-Poly1305 AEAD (256-bit)
- Argon2id KDF (64MB mem, 3 iters, 4 parallel)
- Unique nonces
- Tamper detection

## Usage

1. Add files
2. Enter/confirm passphrase 
3. Select compression (None/Low/Medium/High), optional delete
4. Encrypt/Decrypt

Outputs: `encrypt_output/` (.frnki files), `decrypt_output/` (decrypted files)

## Best Practices

- Strong passphrases: Mixed case, numbers, symbols
- Backup originals
- No recovery: Remember passphrases
- Verify decryption

## Technical Details

- Custom format with validation
- 4KB streaming
- zlib compression (optional)
- Offline, cross-platform
- No network/install

## Requirements

- Linux: x86_64
- Windows: 64-bit, Win7+

## Troubleshooting

- Linux: `chmod +x`, check `file crypt.frnki`
- Windows: 64-bit OS
- AV false positives: Add exception

## License

Educational/security use only. See LICENSE (MIT).

---

⚠️ **Important**: Strong encryption—no recovery. Backup and verify.