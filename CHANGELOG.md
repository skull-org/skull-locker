# Changelog

## 0.1.0 - 11 November 2026 (beta)

First public release.

* Lock and unlock one file with a password and an optional recovery key (64 hex characters, confirmed before locking).
* Argon2id (64 MiB, 3 passes) and XChaCha20-Poly1305 secretstream in 64 KiB chunks; the header is authenticated.
* The original is removed only after the locked copy has been unlocked and its content hash compared.
* Windows right-click entries (per user, no admin rights) and a small password window.
* Three independent reviews by Claude Opus; every high finding fixed (docs/reviews/).
* 61 tests on Linux, Windows and macOS, a stress run and a known-answer file.
