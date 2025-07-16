# Changelog

## v1.0.1 (2025-07-16)
- **Critical:** Fixed decompression bug causing data loss
- Enhanced Argon2id parameters (4 iterations, 128MB memory)
- Themed dialogs with consistent error handling
- Passphrase strength warnings (encryption only)
- Show/hide passphrase toggles
- Improved delete confirmation dialog clarity
- **Security:** Even strong GPU farms would need 28-70 million years to crack 12-character mixed passphrases

## v1.0.0 (2025-07-15)
- Initial public release with hardened security
- Argon2id (64MB mem, 3 iters, 4 parallel)
- Passphrase confirmation
- Compression options including None
- Pathlib integration