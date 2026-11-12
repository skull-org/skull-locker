# skull-locker: design and threat model

_10 Nov 2026. Updated the same day to match the code (`skull_locker/`) after two independent reviews by Claude
Opus (`docs/reviews/`). Where the code and this document differ, the code is wrong or this document is - fix one._

## 1. Threat model
| We protect against | We do NOT protect against (said plainly to the user) |
|---|---|
| Someone who gets the locked file: a lost laptop or USB stick, a shared PC, a copy in email or the cloud | Malware on the PC while you type the password (keyloggers, remote access) |
| Someone who tries passwords: each try costs 64 MiB and 3 Argon2id passes | A weak password (we refuse fewer than 8 non-space characters and suggest a passphrase; no strength meter yet) |
| Tampering: any changed, removed, reordered or added byte is detected; nothing is written out | Someone who sees the file while it is unlocked and open |
| Partial writes: a crash never leaves you with neither the original nor the locked copy | Lost password AND lost recovery key - nobody, including us, can open it |
| A crafted `.skull` file: it cannot hang the PC, crash the app, write outside its folder or hide a program's real name | **Older copies of the original**: one overwrite with zeros cannot reach backups, OneDrive / Dropbox version history, Windows shadow copies, editor autosaves or SSD spare blocks. Lock a file BEFORE it goes into a synced folder - the app says this after every lock |
| A planted file next to the one you right-click (a fake `json.py` or `skull_locker/`): it never runs | Secrets in memory: Python cannot wipe strings, so the password can reach the swap / hibernation file or a crash dump |

## 2. Cryptography (proven parts only, never our own) - libsodium through PyNaCl
- **Password -> key-encryption key:** Argon2id, 64 MiB, 3 passes, a random 16-byte salt per file. The password is
  Unicode NFC-normalised first, so the same Hindi or accented password typed on another keyboard opens the file.
  `lock()` refuses anything weaker; `unlock()` refuses a file asking for more than 256 MiB or 10 passes.
- **File key:** a random 256-bit key per file, wrapped (XChaCha20-Poly1305 AEAD, its own random nonce) once by the
  password key and, optionally, once by the recovery key.
- **Subkeys:** from the file key, keyed BLAKE2b (the libsodium `crypto_kdf` construction, context `SKULLkey`): id 1 =
  the stream key, id 2 = the name key.
- **Content:** XChaCha20-Poly1305 secretstream in 64 KiB chunks, each authenticated; the last chunk is tagged FINAL,
  so cutting, reordering, duplicating or appending is detected.
- **Recovery key (optional):** 256 random bits shown ONCE as 64 hex characters in 8 groups, BEFORE anything is locked;
  the user must type one random group back. Spaces, dashes and letter case are ignored when it is used. (No checksum
  yet - see section 6.)

## 3. File format `.skull` (version 1)
```
"SKULLv1\0" | 4-byte big-endian header length (max 1 MiB) | header (JSON) | secretstream header (24 bytes) | chunks
header = {"v": 1, "alg": "xchacha20poly1305-secretstream", "chunk": 65536, "subkeys": true, "norm": "NFC",
          "kdf": {"alg": "argon2id", "ops": 3, "mem": 67108864, "salt": <hex>},
          "keys": [{"by": "password", "nonce": <hex>, "key": <hex>}, {"by": "recovery", ...}],   (1 or 2, no repeats)
          "name": {"nonce": <hex>, "ct": <hex>}}                                                 (the encrypted name)
```
- The magic bytes and the exact header bytes are the associated data of the FIRST chunk, so any change to the header
  fails the first chunk. The header shape is checked strictly before anything in it is used; only this one format is
  accepted.
- The locked file gets a random name (`<16 hex>.skull`); the original name is only inside, encrypted.

## 4. How it behaves
- **Lock:** refuses links and hard-linked files -> encrypts into a private temp file in the same folder
  (`.skull-XXXX.tmp`, never named after the original) -> fsync -> **verifies by unlocking it the way a user will**:
  the key derived again from the password and the header on disk (and separately from the recovery key), every chunk
  checked, the content hash compared -> renames to `<random>.skull` and syncs the folder -> if the original changed
  while it was being locked, keeps it and says so -> otherwise overwrites it with zeros in 64 KiB pieces and deletes it.
  If the delete fails, the message says the data is safe in the `.skull` file.
- **Unlock:** decrypts into a private temp file (`.unlocking-XXXX.tmp`) -> every chunk and the final tag verified ->
  the restored name is cleaned (no path parts, no `:`, no invisible / direction characters, no device names like
  `CON`, cut to 200 characters keeping the extension) -> the name is claimed atomically (`O_EXCL`), so an existing
  file is never overwritten (`a (1).txt` instead) -> rename. A program or script inside gets a warning, and Windows'
  "downloaded from the internet" mark is copied from the `.skull` file when it has one.
- **Errors:** a wrong password / recovery key (`WrongSecret`) is told apart from a damaged or cut file (`Damaged`).
  A crash in the window shows what exists now; the error log holds only the error type and our own code lines -
  never a file name or path.
- **Windows:** a per-user right-click entry (no admin): "Lock with SKULL" on files (not on `.skull`, one file at a
  time), "Unlock with SKULL" on `.skull`. It runs `pythonw -P -E skull_launch.pyw` (Python 3.11+); the launcher,
  written at install, loads the locker from its own folder by absolute path (no code on the command line). Command line: `python -m skull_locker lock|unlock|install-menu|remove-menu`.
- **Not yet:** folders (lock each file, or zip first), restoring the original timestamps and permissions.

## 5. Tests (`tests/`, 63 today)
Done: every edge size (0, 1, a chunk -1 / exact / +1, 3 chunks + 17); wrong password and recovery key; flipped bytes
across a two-chunk file; truncation mid-chunk and at a chunk boundary; middle chunks swapped / duplicated; a header
from another file spliced on; crafted headers (huge memory or passes, 2,000 keys, wrong version / algorithm, non-JSON
objects, deep nesting, other formats) refused within 2 seconds; NFC vs NFD passwords; recovery keys with spaces /
upper case and malformed ones; a file changing during lock; hard links; a broken password or recovery wrap caught
before the original is touched; the original in use; the destination name appearing during unlock (with and without
hard links); unsafe restored names; whitespace passwords; the real default settings; the right-click command run for
real from folders with planted `json.py` / `skull_locker/` and a `'` in the name; the error log without file names;
60 random round trips.

## 6. Still open before a public release
1. DONE 10 Nov: a fixed `.skull` file (`tests/data/skull_v1_sample.skull`) must always open; the subkeys are checked
   against the libsodium KDF construction. Still to add: a check against libsodium itself (PyNaCl lacks crypto_kdf).
2. Crash injection (kill the process at every step of lock and unlock) and one multi-GB file with bounded memory.
3. Header fuzzing with a property-testing tool, beyond today's fixed cases.
4. Opening the original once (one handle, no path re-opening) and re-hashing it just before the wipe (review 2 #5).
5. A recovery key with a checksum (or words), so a typo is caught at once (review 2 #12).
6. A password strength meter (review 2 #13); restoring timestamps (#16). Stale temp files: DONE (removed after an
   hour, the next time SKULL runs in that folder). The header still shows the file size and the NAME LENGTH (review 3 #12).
7. For programs restored from a `.skull` that came without a "downloaded" mark: add the mark or warn louder (#8).
8. An independent human audit before version 1.0.

## 7. Getting people to use it
README with a 30-second GIF; a comparison page (vs VeraCrypt / Cryptomator / 7-Zip / "folder lock" apps); GitHub
topics; a "Show HN" and r/opensource / r/privacy post; LinkedIn posts by Marketing; releases signed; issues answered
within a day; a Hindi / English UI.
