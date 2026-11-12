# SKULL Locker (open-source file locker) - independent review by Claude Opus (claude-opus-5-5)

> 10 Nov 2026 · code fingerprint 8e982d34ef5e77de · read-only review (no tools). Each fix is decided by the test suite.

## Verdict
**READY AFTER FIXES.** I found no critical or high issues. The cryptography and the authentication of the header and stream hold up, but these must be fixed first:
- the wipe re-opens the original by path, and the change check looks only at size and modification time
- plaintext temp files are left behind after a crash
- the right-click entry breaks when the install path contains `'`
- the recovery-key check is weak (one group of eight, no checksum)
- there are no known-answer tests
- the test file I was given is much smaller than the design doc says

## Findings

| # | Severity | Where (file:function) | Problem | Fix |
|---|---|---|---|---|
| 1 | medium | `locker.py:lock` (the wipe step, `_identity`) | The original is opened by path up to three times: to read it, to stat it, and to wipe it (`open(src, "r+b")`). Both stat and open follow symlinks, and the change check compares only `(st_size, st_mtime_ns)`. Two failures follow. (a) Someone else who can write to the folder sets their file's size and mtime to match a victim file, then swaps the original for a symlink to it after the first check. That victim file gets zeroed if the user can write to it. (b) A change that keeps the mtime gets through: tools that restore timestamps, or 2-second resolution on FAT. The newer content is then destroyed while the `.skull` holds the older one. (Design doc §6 item 4 already lists this.) | Open the original **once**, with `O_NOFOLLOW` on POSIX and a reparse-point check on Windows. Read, `fstat` (compare `st_dev`, `st_ino`, size and mtime), re-hash and zero through **that same handle**. Wipe only if the re-hash equals `plain_hash`. |
| 2 | medium | `locker.py:unlock` / `_decrypt_to` | Plaintext goes to `.unlocking-*.tmp` in the destination folder while decryption runs. Truncation is only detected at the end, so a cut or damaged file still puts almost all of its plaintext on disk first. After a kill or power loss, that temp file stays as plaintext. On failure it is unlinked, not wiped. On Windows `mkstemp` is not private (the file takes the folder's permissions). In OneDrive or Dropbox folders the partial plaintext may be uploaded before it is deleted. | Make two passes: first authenticate the whole stream with no output (all chunks plus the FINAL tag), then decrypt to the temp file. Mark the temp file hidden and temporary. Remove stale `.unlocking-*.tmp` files at startup. Never delete stale `.skull-*.tmp` files (see #10). |
| 3 | medium | `__main__.py:menu_entries` | `{home!r}` switches to **double** quotes when the path contains `'`, for example `C:\Users\O'Brien\...` (a common user-profile name). That ends the outer `-c "..."` early, Windows splits the code into separate arguments, and pythonw exits silently with a SyntaxError. The menu does nothing. The doc's test with `'` covers the clicked file's folder, not the install folder. | Don't build Python source inside the command line. Install a small launcher `.pyw` next to the package and register `"pythonw" -E "<launcher>" gui-lock "%1"`. The script's own folder is then the only folder added to the import path, and that folder is ours. Or pass `home` as its own argument. Test with `'`, spaces and non-ASCII characters in the install path. |
| 4 | medium | `locker.py:safe_name` (`RISKY_EXT`), `_copy_zone` | The deny-list misses many executable and active types: `.html/.htm`, `.svg`, `.xll`, `.xlam`, `.dotm`, `.xltm`, `.potm`, `.ppsm`, `.one`, `.appref-ms`, `.application`, `.website`, `.settingcontent-ms`, `.library-ms`, `.search-ms`, `.ws/.wsh/.wsc/.sct/.vb`, `.inf`, `.sys`, `.gadget`, `.ps1xml/.psd1`, `.msh*`, `.cab`. Also, a `.skull` that arrived without Mark-of-the-Web restores a program with no mark, so SmartScreen never checks it (doc §6 item 7). | Turn it around: warn for anything **not** on a short list of known-safe document types. On Windows, add `ZoneId=3` to any restored file of a risky type when the `.skull` has no mark of its own. |
| 5 | medium | `locker.py:_subkeys` | This re-implements `crypto_kdf_derive_from_key` with BLAKE2b (salt = id in little-endian + 8 zero bytes, person = context + 8 zero bytes). I believe it matches libsodium, but nothing tests it. A bug here, or a later "cleanup", silently changes the format and makes every existing file unreadable. There is also no committed v1 fixture (doc §6 item 1). | Add a known-answer test against libsodium's own `crypto_kdf` output (through ctypes, or vectors taken from libsodium). Commit a v1 `.skull` file and its password, which every future version must open byte-for-byte. |
| 6 | medium | `__main__.py:_gui`, `main` (recovery key flow) | The recovery key is shown once and has no checksum, and the user types back only 1 of its 8 groups. A mistake copying any of the other 7 groups goes unnoticed until the day the key is needed. That defeats the purpose of a recovery key. | Add a checksum outside the 256 bits (for example 2 extra groups from BLAKE2b of the key), checked in `_recovery_bytes` with its own error message. Or use a word list. Ask for the whole key back, or at least 3 random groups. |
| 7 | low | `locker.py:lock`, `__main__.py` | The password rule and the ops/mem limits are only checked inside `lock()`, after the recovery key has been shown and confirmed. A short password fails after the user has already written down a key that will never be used. `lock()` also accepts ops > 10 or mem > 256 MiB. That file then fails its own verification with the misleading "damaged" message. | Add `check_password()` and call it before the recovery-key step. In `lock()`, check both ends of `OPS_RANGE` and `MEM_RANGE`. |
| 8 | low | `locker.py:lock` (password check) | The length check counts spaces in the middle, so `"a      b"` passes. The doc promises "fewer than 8 non-space characters" are refused. | Count non-whitespace characters, or correct the doc. |
| 9 | low | `locker.py:lock` (the change check after locking) | The message says the `.skull` "holds the version from before". If a program wrote to the file while it was being read, the `.skull` may hold a mix of old and new content. | Delete the new `.skull` in that case, or change the message to say it may be incomplete and the file should be locked again. |
| 10 | low (plausible) | `locker.py:_fsync_dir`, `lock` | On Windows, `os.replace` uses `MoveFileEx` without `MOVEFILE_WRITE_THROUGH`. NTFS journaling the rename does not mean the journal reaches disk before the zeroed data does. After a power loss, the original can be zeroed while the locked data survives only as `.skull-*.tmp`. The planned stale-temp cleanup would then delete the only copy. Also, the "verify" step reads back the OS cache, not the disk. | On Windows, rename with `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING \| MOVEFILE_WRITE_THROUGH)` through ctypes. Never auto-delete `.skull-*.tmp`; offer to recover it. Describe the verify step as "re-decrypted", not "read from disk". |
| 11 | low | `locker.py:safe_name` | The name is cut to 200 **characters**, but Linux and macOS limit names to 255 **bytes**. A long Hindi name locked on Windows (3 UTF-8 bytes per character) fails to unlock elsewhere with a raw `OSError` (`ENAMETOOLONG`), not a `LockError`. | Cut by UTF-8 byte length (about 240 bytes, leaving room for ` (n)`). On `ENAMETOOLONG`, fall back to `unlocked<ext>`. |
| 12 | low | file format (`lock`) | The header and file size show the exact plaintext size, the length of the original name, whether a recovery key exists, and the KDF settings. The doc says the name is hidden, but its length is not. | Document this in the threat model. Optionally pad the name to a fixed 255 bytes before encrypting it. |
| 13 | low | `__main__.py:_gui`, `main` | `del pw` wipes nothing. Tk entry widgets and Python strings keep the secret, and the CLI prints the recovery key into the terminal's scrollback. The doc admits Python cannot wipe memory, but the code comment suggests otherwise. | Mark the comment as best-effort only. After the user confirms the key, tell them to clear the terminal or close the window. |
| 14 | low | `locker.py:unlock` (`last_warning`) | The warning is stored as global state on the function. It is not thread-safe, and a caller who reads it after a failed `unlock()` gets the previous file's warning. | Return `(path, warning)` or a small result object. |
| 15 | low | `locker.py:unlock` (claiming the name) | If `os.replace(tmp, dest)` fails after the `O_EXCL` claim, an empty placeholder with the original's name is left behind. | Remove the placeholder in the `except` block when the rename fails. |
| 16 | low | `docs/.../file-locker-design.md` §5 vs `tests/test_skull_locker.py` | The doc claims 53 tests, including chunk reorder and duplicate, header splicing, crafted headers, NFC vs NFD, hard links, a file changing during lock, planted `json.py`, and the error log. The file I was given has 8 test functions (13 cases) and none of those. `test_every_changed_byte_is_caught` flips every 7th byte of a single-chunk file and only checks for the base `LockError`. | If more `test_skull_locker*.py` files exist, include them in the review. Otherwise correct the doc, then write the tests below. |

On the other areas you listed, I found nothing wrong:
- **Nonce and header handling:** fine. The magic bytes and exact header bytes are the first chunk's associated data, and the secretstream header is covered implicitly.
- **Error messages:** no useful leak. The `WrongSecret` vs `Damaged` split tells an attacker nothing they don't already know, and the error log holds no paths.

## Missing tests
1. A known-answer test: `_subkeys` must equal libsodium `crypto_kdf_derive_from_key` for fixed inputs.
2. A committed v1 `.skull` fixture with its password and recovery key, which must always open to a known hash.
3. Middle chunks swapped, duplicated or dropped, plus a file cut **exactly** at a chunk boundary (none of the current cuts land on one).
4. A header from another file spliced on, and a secretstream header from another file spliced on.
5. Flip **every** byte of a multi-chunk file. Check `WrongSecret` for wrong secrets and for changes to the KDF settings or key wraps, and `Damaged` for changes to the content, name, stream header or length prefix.
6. Crafted headers: ops/mem out of range, `true` as ops, 2,000 keys, a repeated `by`, length > 1 MiB, deep nesting, a non-object top level, salt that is not hex, a missing `name`. Each must be refused quickly and with `Damaged`.
7. The same password in NFC and NFD forms, emoji (astral) passwords typed through the CLI and through Tk, and passwords with spaces inside.
8. Recovery key parsing: spaces, dashes and upper case accepted; 63 or 65 characters and non-hex refused. A corrupted recovery wrap must make `lock()` fail before the original is touched.
9. A file changed during lock (change it mid-read). The original must be kept and the message must be accurate.
10. Symlink and hard-link refusal, and a symlink swapped in just before the wipe.
11. The wipe or unlink failing (`PermissionError`): the `.skull` survives and the message is correct.
12. The destination name appearing between the check and the `O_EXCL` claim, and a failing `os.replace` leaving no placeholder.
13. A table of `safe_name` cases: `..\..\x`, `C:evil`, `CON.txt`, `com¹`, `nul .txt`, RTL-override and zero-width names, `...`, the empty name, trailing dots, 300-character names with and without an extension, and long multibyte names (checked by byte length).
14. Risky-extension warnings: mixed case, double extensions, and every type in the list.
15. Crash injection: kill the process at every step of lock and unlock. Afterwards either the original or a verified `.skull` must exist, and no plaintext temp file is left.
16. A multi-GB file with bounded memory (tracemalloc or RSS).
17. The real default settings (`ALLOW_WEAK_KDF=False`): weak settings refused, settings above the limits refused up front.
18. The menu command run for real: an install path with `'`, spaces and non-ASCII characters, and a planted `json.py` / `skull_locker/` in the clicked folder.
19. The GUI and CLI fallback: a 64-hex password vs a recovery key; `Damaged` is never retried as a recovery key.
20. Mark-of-the-Web copied on Windows, and the error log containing no file names or paths.
21. `unlock(out_dir=...)` to another folder, and `remove_locked=False` leaving the `.skull` untouched.

## What is done well
- It uses only proven building blocks: Argon2id, XChaCha20-Poly1305 secretstream and AEAD key wrapping, all from libsodium. There is a random file key and separate subkeys for the stream and the name.
- The exact header bytes are the first chunk's associated data, and the FINAL tag plus the check for data after the end catch cutting and appending.
- The header shape is checked strictly before use, with limits on length, KDF cost and key count, so a crafted file cannot make the app hang.
- Lock verifies the locked copy by deriving the key again from the header on disk, for both the password and the recovery key, before anything is removed. It refuses links, hard links and files that changed during locking.
- Unlock claims the restored name with `O_EXCL` and never overwrites an existing file. Name cleaning removes path parts, `:`, Cc/Cf characters and device names.
- Error messages are consistent: one message for every key failure, a separate "damaged" case, and a crash log with no paths.
- The menu entry is per user, runs with `-P -E`, uses `AppliesTo` and `MultiSelectModel`, and is built by a pure, testable `menu_entries()`.
- The threat model is honest about older copies, SSDs, secrets in memory and synced folders, and the app repeats that warning after every lock.
