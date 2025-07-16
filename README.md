# crypt.frnki v1.0.1

**Military-grade file encryption with zero dependencies.**

## Quick Deploy

### Linux
```bash
chmod +x crypt.frnki && ./crypt.frnki
```

### Windows
```cmd
crypt.frnki.exe
```

No installation. No telemetry. No network calls.

## Repository Structure

```
crypt.frnki.py      # Source code (~27KB)
build.spec          # PyInstaller configuration
favicon.{ico,png}   # Application icons
```

**Releases:** Pre-built binaries available on GitHub
- `crypt.frnki` (Linux x64, ~26MB)
- `crypt.frnki.exe` (Windows x64, ~26MB)

## Security Implementation

### Cryptographic Stack
- **Cipher:** ChaCha20-Poly1305 AEAD (256-bit keys)
- **KDF:** Argon2id (4 iterations, 128MB memory, 4 threads)
- **Nonces:** Cryptographically secure random per-chunk
- **Authentication:** Built-in tamper detection

### Defensive Measures
- Random per-file salts (no rainbow tables)
- Path traversal sanitization
- Input length validation
- Secure memory clearing
- Atomic file operations
- Generic error responses

### Recent Security Fixes (v1.0.1)
- **Critical:** Fixed decompression bug causing data loss
- Enhanced Argon2id parameters (+33% computation, +100% memory)
- Passphrase strength validation
- Per-file error reporting
- Show/hide passphrase toggles

## Usage Protocol

1. **Load:** Select target files
2. **Authenticate:** Enter passphrase (confirmed)
3. **Configure:** Compression level, deletion options
4. **Execute:** Encrypt or decrypt operation

**Output directories:**
- `encrypt_output/` → `.frnki` encrypted files
- `decrypt_output/` → Original files restored

## Operational Security

**Passphrase Guidelines:**
- Minimum 12 characters recommended
- Use high-entropy sources (password managers)
- No passphrase recovery mechanism exists

**File Handling:**
- Verify decryption before deleting originals
- Test with non-critical files first
- Keep encrypted backups in separate locations

## Technical Specifications

**File Format:** Custom binary with integrity validation  
**Streaming:** 4KB chunks (memory-efficient for large files)  
**Compression:** Optional zlib (None/Low/Medium/High)  
**Platform:** Cross-platform Python 3.8+  
**Dependencies:** Bundled (cryptography, argon2, PIL)

## System Requirements

**Linux:** x86_64, glibc 2.17+  
**Windows:** x64, Windows 7 SP1+  

## Troubleshooting

**Permission denied (Linux):**
```bash
chmod +x crypt.frnki
```

**False positive detection:**
Add binary to antivirus exceptions. PyInstaller executables commonly trigger heuristics.

**File type verification:**
```bash
file crypt.frnki  # Should show: ELF 64-bit LSB executable
```

## License

MIT License. Educational and defensive security use.

---

⚠️ **OPSEC Warning:** Strong encryption = no recovery. Verify before deleting originals.