"""skull-locker - lock a file with a password, using only proven cryptography. See docs/design.md.

Proven cryptography only, through libsodium (PyNaCl):
  * the key from the password: Argon2id (64 MiB, 3 passes, a random 16-byte salt per file); the password is NFC-
    normalised first, so the same Hindi / accented password typed on another keyboard opens the file
  * the file: XChaCha20-Poly1305 secretstream in 64 KiB chunks, each authenticated, the last one marked FINAL
  * the header (format, salt, parameters, the wrapped file key, the encrypted original name) is authenticated as the
    first chunk's associated data - any changed byte anywhere is detected; nothing is written out
  * separate subkeys (libsodium KDF) for the stream and for the name
  * an optional recovery key (256 bits, shown once) wraps the same file key a second time

Lock never loses the original: the locked copy is written to a temp file, fsynced, then verified by unlocking it the
way a user would (the key derived again from the password and the header ON DISK, the recovery key checked too),
renamed into place, the folder synced, and only then is the original overwritten (in chunks) and removed - unless it
changed while it was being locked. Unlock writes to a private temp file and never overwrites an existing file.

10 Nov 2026: hardened after the independent review by Claude Opus (docs/reviews/);
each fix carries its finding number (#n).

    lock(path, password, recovery_key=None) -> the .skull path
    unlock(path, password=None, recovery_key=None, out_dir=None) -> the restored path
    new_recovery_key() -> 64 hex characters (show it to the user ONCE)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import struct
import tempfile
import unicodedata
from pathlib import Path

import nacl.bindings as nb
from nacl import pwhash

MAGIC = b"SKULLv1\0"
VERSION = 1
ALG = "xchacha20poly1305-secretstream"
CHUNK = 64 * 1024
OPS, MEM = 3, 64 * 1024 * 1024                     # Argon2id: 3 passes, 64 MiB
OPS_RANGE = (1, 10)                                 # #5 / review 2 #4: limits a crafted header cannot go past
MEM_RANGE = (8 * 1024 * 1024, 256 * 1024 * 1024)
MIN_OPS, MIN_MEM = OPS, MEM                         # review 2 #4: lock() never makes a file cheaper to guess
ALLOW_WEAK_KDF = False                              # the test suite only (fast Argon2) - never set in the product
MIN_PASSWORD = 8
SS = "crypto_secretstream_xchacha20poly1305"
TAG_MSG = nb.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
TAG_FINAL = nb.crypto_secretstream_xchacha20poly1305_TAG_FINAL
ABYTES = nb.crypto_secretstream_xchacha20poly1305_ABYTES
KDF_CTX = b"SKULLkey"                               # 8 bytes, libsodium crypto_kdf context (#13)
WRONG = "wrong password or recovery key, or the file was changed"
DAMAGED = "the file is damaged or was changed"
RESERVED = re.compile(r"^(?:con|prn|aux|nul|conin\$|conout\$|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])\s*(?:\..*)?$", re.I)
UNSAFE_CHARS = re.compile(r"[:<>\"/\\|?*]")        # + every Cc / Cf character (_visible)
RISKY_EXT = {".html", ".htm", ".svg", ".xll", ".xlam", ".dotm", ".xltm", ".potm", ".ppsm", ".one", ".appref-ms",
             ".application", ".website", ".settingcontent-ms", ".library-ms", ".search-ms", ".ws", ".wsh", ".wsc",
             ".sct", ".vb", ".inf", ".reg", ".msc", ".msp", ".scf", ".url", ".chm", ".dll", ".appx", ".msix", ".psm1", ".docm", ".xlsm",
             ".pptm", ".iso", ".img", ".vhd", ".vhdx", ".exe", ".bat", ".cmd", ".com", ".scr", ".pif", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".ps1", ".msi",
             ".lnk", ".hta", ".cpl", ".jar"}


def password_problem(password: str | None) -> str:
    """Review 3 #7 / #8: the one password rule - at least MIN_PASSWORD characters that are not spaces."""
    if not password or len("".join(unicodedata.normalize("NFC", password).split())) < MIN_PASSWORD:
        return f"use a password of at least {MIN_PASSWORD} characters, not counting spaces (a passphrase of 4+ words is better)"
    return ""


class LockError(Exception):
    """Wrong password / recovery key, a damaged or tampered file, or not a .skull file."""


class WrongSecret(LockError):
    """The password / recovery key does not open this file (the file itself may be fine)."""


class Damaged(LockError):
    """The file is cut short, changed or not a SKULL file - another password will not help."""


def new_recovery_key() -> str:
    return secrets.token_hex(32)


def _recovery_bytes(recovery_key: str) -> bytes:
    """#17 / #10: spaces, dashes and letter case do not matter; anything else that is not 64 hex characters is refused."""
    k = re.sub(r"[\s-]", "", str(recovery_key or "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", k):
        raise LockError("a recovery key is 64 characters (0-9 and a-f)")
    return bytes.fromhex(k)


def _kdf(password: str, salt: bytes, ops: int = OPS, mem: int = MEM) -> bytes:
    pw = unicodedata.normalize("NFC", password)    # #6
    return pwhash.argon2id.kdf(32, pw.encode("utf-8"), salt, opslimit=ops, memlimit=mem)


def _subkeys(key: bytes) -> tuple[bytes, bytes]:
    """#13: one random file key -> a stream key and a name key (domain separation). The same construction as
    libsodium's crypto_kdf (keyed BLAKE2b with a subkey id as salt and a context as personalisation), which PyNaCl
    does not expose directly."""
    from nacl.encoding import RawEncoder
    from nacl.hash import blake2b

    def sub(i: int) -> bytes:
        return blake2b(b"", digest_size=32, key=key, salt=struct.pack("<Q", i) + bytes(8),
                       person=KDF_CTX + bytes(8), encoder=RawEncoder)
    return sub(1), sub(2)


def _wrap(kek: bytes, key: bytes) -> dict:
    nonce = secrets.token_bytes(24)
    ct = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(key, b"skull-key", nonce, kek)
    return {"nonce": nonce.hex(), "key": ct.hex()}


def _unwrap(kek: bytes, w: dict) -> bytes:
    try:
        return nb.crypto_aead_xchacha20poly1305_ietf_decrypt(bytes.fromhex(w["key"]), b"skull-key",
                                                             bytes.fromhex(w["nonce"]), kek)
    except Exception:  # noqa: BLE001 - one message for every failure: never say which part was wrong
        raise WrongSecret(WRONG) from None


def _fsync_write(f) -> None:
    f.flush()
    os.fsync(f.fileno())


def _fsync_dir(d: Path) -> None:
    """#7: make a rename durable before the other copy goes (POSIX; Windows NTFS journals the rename)."""
    if os.name == "nt":
        return
    try:
        fd = os.open(str(d), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _identity(p: Path) -> tuple:
    st = p.stat()
    return (st.st_size, st.st_mtime_ns)


def lock(path, password: str, recovery_key: str | None = None, *, ops: int = OPS, mem: int = MEM,
         remove_original: bool = True) -> Path:
    src = Path(path)
    if src.is_symlink():                                                # #12
        raise LockError(f"{src.name} is a shortcut (link) - lock the file it points to instead")
    if not src.is_file():
        raise LockError(f"not a file: {src}")
    if remove_original and src.stat().st_nlink > 1:                     # #12
        raise LockError(f"{src.name} has other names (hard links) - removing it would erase those too")
    if password_problem(password):
        raise LockError(password_problem(password))
    if not ALLOW_WEAK_KDF and (ops < MIN_OPS or mem < MIN_MEM):            # review 2 #4
        raise LockError("the key settings are weaker than SKULL allows")
    if not (OPS_RANGE[0] <= ops <= OPS_RANGE[1] and MEM_RANGE[0] <= mem <= MEM_RANGE[1]):    # review 3 #7
        raise LockError("the key settings are outside what SKULL can open again")
    clean_stale(src.parent)
    rec = _recovery_bytes(recovery_key) if recovery_key else None
    before = _identity(src)
    key = nb.crypto_secretstream_xchacha20poly1305_keygen()
    k_stream, k_name = _subkeys(key)
    salt = secrets.token_bytes(pwhash.argon2id.SALTBYTES)
    wrapped = [{"by": "password", **_wrap(_kdf(password, salt, ops, mem), key)}]
    if rec:
        wrapped.append({"by": "recovery", **_wrap(rec, key)})
    name_nonce = secrets.token_bytes(24)
    name_ct = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(src.name.encode("utf-8"), b"skull-name", name_nonce, k_name)
    header = json.dumps({"v": VERSION, "alg": ALG, "chunk": CHUNK, "subkeys": True, "norm": "NFC",
                         "kdf": {"alg": "argon2id", "ops": ops, "mem": mem, "salt": salt.hex()}, "keys": wrapped,
                         "name": {"nonce": name_nonce.hex(), "ct": name_ct.hex()}}, separators=(",", ":")).encode()
    out = src.with_name(secrets.token_hex(8) + ".skull")
    fd, tmp_name = tempfile.mkstemp(prefix=".skull-", suffix=".tmp", dir=str(src.parent))   # #11
    tmp = Path(tmp_name)
    state = nb.crypto_secretstream_xchacha20poly1305_state()
    ss_header = nb.crypto_secretstream_xchacha20poly1305_init_push(state, k_stream)
    plain_hash = hashlib.sha256()
    try:
        with open(src, "rb") as fin, os.fdopen(fd, "wb") as fout:
            fout.write(MAGIC + struct.pack(">I", len(header)) + header + ss_header)
            ad = MAGIC + header                     # the header is authenticated by the first chunk
            chunk = fin.read(CHUNK)
            while True:
                nxt = fin.read(CHUNK)
                tag = TAG_FINAL if not nxt else TAG_MSG
                plain_hash.update(chunk)
                fout.write(nb.crypto_secretstream_xchacha20poly1305_push(state, chunk, ad, tag))
                ad = None
                if not nxt:
                    break
                chunk = nxt
            _fsync_write(fout)
        # #2: verify the locked copy the way a user will open it - the key derived AGAIN from the password and the
        # header read from disk (and the recovery key on its own), every chunk checked, the content hash compared
        for by in (["password"] + (["recovery"] if rec else [])):
            got = hashlib.sha256()
            _decrypt_to(tmp, key_from=lambda h, by=by: _key_from(h, password if by == "password" else None,
                                                                 recovery_key if by == "recovery" else None,
                                                                 only=by), out=None, digest=got)
            if got.digest() != plain_hash.digest():
                raise LockError("the locked copy did not match the original - nothing was changed")
        os.replace(tmp, out)
        _fsync_dir(out.parent)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    if remove_original:
        if _identity(src) != before:                                      # #4 / review 3 #9
            out.unlink(missing_ok=True)       # it may hold a mix of old and new content - never keep that
            raise LockError(f"{src.name} changed while it was being locked, so nothing was locked and the original "
                            f"was NOT touched. Close the program using it and try again")
        try:
            size = src.stat().st_size
            zero = b"\0" * CHUNK
            with open(src, "r+b") as f:             # #3: one overwrite pass, in chunks (never the whole file in RAM)
                left = size
                while left > 0:
                    n = min(CHUNK, left)
                    f.write(zero[:n])
                    left -= n
                _fsync_write(f)
            src.unlink()
        except OSError as e:
            raise LockError(f"locked safely as {out.name}, but the original could not be fully removed "
                            f"({e.strerror or e}). It may already be overwritten with zeros - your data is in {out.name}. "
                            f"Close any program using {src.name} and delete it yourself") from None
    return out


def _read_header(f) -> tuple[dict, bytes, bytes]:
    if f.read(len(MAGIC)) != MAGIC:
        raise Damaged("not a SKULL locked file")
    raw_len = f.read(4)
    if len(raw_len) != 4:
        raise Damaged(DAMAGED)
    n = struct.unpack(">I", raw_len)[0]
    if n > 1 << 20:
        raise Damaged(DAMAGED)
    raw = f.read(n)
    try:
        header = json.loads(raw)
    except (ValueError, RecursionError):
        raise Damaged(DAMAGED) from None
    _check_header(header)
    ss_header = f.read(nb.crypto_secretstream_xchacha20poly1305_HEADERBYTES)
    if len(ss_header) != nb.crypto_secretstream_xchacha20poly1305_HEADERBYTES:
        raise Damaged(DAMAGED)
    return header, raw, ss_header


def _check_header(h) -> None:
    """#5 / #14: a strict shape BEFORE anything is used - a crafted header cannot hang the machine or crash the app."""
    try:
        ok = (isinstance(h, dict) and h.get("v") == VERSION and h.get("alg") == ALG and h.get("chunk") == CHUNK
              and isinstance(h.get("kdf"), dict) and h["kdf"].get("alg") == "argon2id"
              and isinstance(h["kdf"].get("ops"), int) and OPS_RANGE[0] <= h["kdf"]["ops"] <= OPS_RANGE[1]
              and isinstance(h["kdf"].get("mem"), int) and MEM_RANGE[0] <= h["kdf"]["mem"] <= MEM_RANGE[1]
              and isinstance(h["kdf"].get("salt"), str) and len(h["kdf"]["salt"]) == 2 * pwhash.argon2id.SALTBYTES
              and isinstance(h.get("keys"), list) and 1 <= len(h["keys"]) <= 2
              and all(isinstance(w, dict) and w.get("by") in ("password", "recovery") for w in h["keys"])
              and len({w["by"] for w in h["keys"]}) == len(h["keys"])
              and isinstance(h.get("name"), dict) and h.get("subkeys") is True and h.get("norm") == "NFC")
    except Exception:  # noqa: BLE001
        ok = False
    if not ok:
        raise Damaged(DAMAGED)


def _key_from(header: dict, password: str | None, recovery_key: str | None, *, only: str = "") -> bytes:
    for w in header["keys"]:
        by = w["by"]
        if only and by != only:
            continue
        try:
            if by == "password" and password is not None:
                k = header["kdf"]
                return _unwrap(_kdf(password, bytes.fromhex(k["salt"]), k["ops"], k["mem"]), w)   # one KDF run (#5)
            if by == "recovery" and recovery_key:
                return _unwrap(_recovery_bytes(recovery_key), w)
        except (LockError, ValueError, KeyError, TypeError):
            continue
    raise WrongSecret(WRONG)


def _decrypt_to(path: Path, *, key_from, out, digest=None) -> str:
    """Decrypt + verify every chunk; write to `out` (a file object) when given. Returns the original name."""
    with open(path, "rb") as f:
        header, raw, ss_header = _read_header(f)
        key = key_from(header)
        k_stream, k_name = _subkeys(key)
        state = nb.crypto_secretstream_xchacha20poly1305_state()
        try:
            nb.crypto_secretstream_xchacha20poly1305_init_pull(state, ss_header, k_stream)
        except Exception:  # noqa: BLE001
            raise Damaged(DAMAGED) from None
        ad, final = MAGIC + raw, False
        while True:
            c = f.read(CHUNK + ABYTES)
            if not c:
                break
            if final:
                raise Damaged("the file was changed (data after the end)")
            try:
                m, tag = nb.crypto_secretstream_xchacha20poly1305_pull(state, c, ad)
            except Exception:  # noqa: BLE001
                raise Damaged(DAMAGED) from None       # #16: the key was right - the CONTENT is damaged
            ad = None
            if out is not None:
                out.write(m)
            if digest is not None:
                digest.update(m)
            final = tag == TAG_FINAL
        if not final:
            raise Damaged("the file is cut short (it was not completely written or was changed)")
        nm = header["name"]
        try:
            return nb.crypto_aead_xchacha20poly1305_ietf_decrypt(bytes.fromhex(nm["ct"]), b"skull-name",
                                                                bytes.fromhex(nm["nonce"]), k_name).decode("utf-8")
        except Exception:  # noqa: BLE001
            raise Damaged(DAMAGED) from None


def _visible(text: str) -> str:
    """Drop every control / format character (Unicode Cc and Cf): direction overrides, zero-width marks, BOMs."""
    return "".join(ch for ch in text if unicodedata.category(ch) not in ("Cc", "Cf"))


def safe_name(name: str) -> tuple[str, str]:
    """#9 / review 2 #2: the restored name comes from whoever made the file. Cleaned in this order: drop ':' (a
    drive or an alternate stream) and path parts, drop invisible characters and unsafe symbols, CUT to 200 keeping
    the extension, strip trailing dots / spaces (Windows drops them), and only then check device names and risky
    extensions - on the exact name that will be created. Returns (name, warning)."""
    n = Path(str(name or "").replace(":", "")).name
    n = UNSAFE_CHARS.sub("", _visible(unicodedata.normalize("NFC", n))).strip().rstrip(". ")
    if len(n.encode("utf-8")) > 200 or len(n) > 200:                 # review 3 #11: bytes, not characters
        stem, suf = (n.rsplit(".", 1) + [""])[:2] if "." in n[-12:] else (n, "")
        room = 200 - len(suf.encode("utf-8")) - (1 if suf else 0)
        while len(stem.encode("utf-8")) > room:
            stem = stem[:-1]
        n = stem + ("." + suf if suf else "")
    n = n.strip().rstrip(". ")
    if not n or n in (".", "..") or RESERVED.match(n):
        suf = Path(n).suffix if n and RESERVED.match(n) else ""
        n = "unlocked" + suf
    ext = Path(n).suffix.rstrip(". ").lower()
    warn = f"{n} is a program or script - open it only if you trust who sent it" if ext in RISKY_EXT else ""
    return n, warn


STALE_SECONDS = 3600


def clean_stale(folder: Path) -> int:
    """Review 3 #2: a crash can leave our own temp files (.unlocking-*.tmp holds plaintext). They are removed - after
    one overwrite pass - the next time SKULL runs in that folder, once they are an hour old (so a lock or unlock still
    running elsewhere is never touched)."""
    import time
    gone = 0
    for pat in (".unlocking-*.tmp", ".skull-*.tmp"):
        for t in Path(folder).glob(pat):
            try:
                if time.time() - t.stat().st_mtime < STALE_SECONDS:
                    continue
                size = t.stat().st_size
                with open(t, "r+b") as f:
                    f.write(b"\0" * min(size, 64 * 1024 * 1024))
                t.unlink()
                gone += 1
            except OSError:
                pass
    return gone


def unlock(path, password: str | None = None, recovery_key: str | None = None, *, out_dir=None,
           remove_locked: bool = True) -> Path:
    src = Path(path)
    dest_dir = Path(out_dir) if out_dir else src.parent
    clean_stale(dest_dir)
    fd, tmp_name = tempfile.mkstemp(prefix=".unlocking-", suffix=".tmp", dir=str(dest_dir))   # #11
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fout:
            name = _decrypt_to(src, key_from=lambda h: _key_from(h, password, recovery_key), out=fout)
            _fsync_write(fout)
        name, warn = safe_name(name)
        stem, suf = Path(name).stem, Path(name).suffix
        n = 0
        while True:                       # #11 / review 2 #1: claim the name atomically, never overwrite
            dest = dest_dir / (name if n == 0 else f"{stem} ({n}){suf}")
            try:
                fd2 = os.open(str(dest), os.O_CREAT | os.O_EXCL | os.O_WRONLY)   # fails if the name exists
            except FileExistsError:
                n += 1
                continue
            os.close(fd2)
            try:
                os.replace(tmp, dest)        # over OUR OWN empty placeholder - nobody else's file
            except OSError:
                dest.unlink(missing_ok=True)  # review 3 #15: never leave an empty file with the original's name
                raise
            break
        _fsync_dir(dest_dir)
        _copy_zone(src, dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    if remove_locked:
        src.unlink()
    unlock.last_warning = warn
    return dest


unlock.last_warning = ""


def _copy_zone(src: Path, dest: Path) -> None:
    """#9: keep Windows' 'downloaded from the internet' mark, so SmartScreen still checks an unlocked program."""
    if os.name != "nt":
        return
    try:
        zone = Path(str(src) + ":Zone.Identifier").read_bytes()
        Path(str(dest) + ":Zone.Identifier").write_bytes(zone)
    except OSError:
        pass
