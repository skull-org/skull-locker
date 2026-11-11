"""10 Nov 2026: the fixes for Claude Opus's independent review of the SKULL locker (docs/reviews/), one test each."""
import json
import os
import struct
import subprocess
import sys
import time
import unicodedata

import pytest

from skull_locker import locker as L

FAST = {"ops": 1, "mem": 8 * 1024 * 1024}


@pytest.fixture(autouse=True)
def _fast_kdf(monkeypatch):
    monkeypatch.setattr(L, "ALLOW_WEAK_KDF", True)

PW = "correct horse battery"


def _lock(tmp_path, data=b"secret data", name="a.txt", **k):
    f = tmp_path / name
    f.write_bytes(data)
    return L.lock(f, k.pop("pw", PW), k.pop("rk", None), **FAST, **k)


def test_1_the_right_click_command_never_runs_planted_code(tmp_path):
    from skull_locker import __main__ as M
    planted = tmp_path / "downloads"
    (planted / "skull_locker").mkdir(parents=True)
    marker = tmp_path / "PWNED"
    evil = f"open(r'{marker}', 'w').write('x')\n"
    (planted / "skull_locker" / "__init__.py").write_text(evil)
    (planted / "skull_locker" / "__main__.py").write_text(evil)
    (planted / "json.py").write_text(evil)
    victim = planted / "report.txt"
    victim.write_text("hi")
    M.write_launcher()
    cmd = M.menu_entries(sys.executable)[M.MENU_LOCK][1]
    assert " -P " in cmd and " -m skull_locker" not in cmd
    cmd = cmd.replace("gui-lock", "help").replace('"%1"', f'"{victim}"')
    r = subprocess.run(cmd, shell=True, cwd=str(planted), capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert not marker.exists()                                   # nothing planted in the folder ran


def test_2_a_broken_key_wrap_stops_the_lock_and_keeps_the_original(tmp_path, monkeypatch):
    real = L._wrap
    monkeypatch.setattr(L, "_wrap", lambda kek, key: real(kek, bytes(32)))     # wraps the WRONG key
    f = tmp_path / "keep.txt"
    f.write_text("precious")
    with pytest.raises(L.LockError):
        L.lock(f, PW, **FAST)
    assert f.read_text() == "precious" and not list(tmp_path.glob("*.skull"))


def test_2b_a_broken_recovery_wrap_is_caught_too(tmp_path, monkeypatch):
    real = L._wrap
    calls = []

    def wrap(kek, key):
        calls.append(1)
        return real(kek, key if len(calls) == 1 else bytes(32))   # the password entry is fine, the recovery one is not
    monkeypatch.setattr(L, "_wrap", wrap)
    f = tmp_path / "keep.txt"
    f.write_text("precious")
    with pytest.raises(L.LockError):
        L.lock(f, PW, L.new_recovery_key(), **FAST)
    assert f.read_text() == "precious"


def test_3_the_original_is_overwritten_in_chunks_and_a_locked_original_is_reported(tmp_path, monkeypatch):
    f = tmp_path / "big.bin"
    f.write_bytes(os.urandom(3 * L.CHUNK + 5))
    real_unlink = type(f).unlink

    def refuse(self, *a, **k):
        if self.name == "big.bin":
            raise PermissionError(13, "in use")
        return real_unlink(self, *a, **k)
    monkeypatch.setattr(type(f), "unlink", refuse)
    with pytest.raises(L.LockError, match="locked safely"):
        L.lock(f, PW, **FAST)
    assert len(list(tmp_path.glob("*.skull"))) == 1              # the locked copy exists and is reported


def test_4_a_file_that_changes_while_locking_is_not_removed(tmp_path, monkeypatch):
    f = tmp_path / "live.log"
    f.write_text("line 1\n")
    real = L._decrypt_to

    def append_then(*a, **k):
        with open(f, "a") as h:
            h.write("line 2 written during the lock\n")
        return real(*a, **k)
    monkeypatch.setattr(L, "_decrypt_to", append_then)
    with pytest.raises(L.LockError, match="changed while"):
        L.lock(f, PW, **FAST)
    assert "line 2" in f.read_text()                             # nothing was zeroed or deleted


def _with_header(locked, change):
    raw = locked.read_bytes()
    n = struct.unpack(">I", raw[8:12])[0]
    h = json.loads(raw[12:12 + n])
    h = change(h)
    nh = json.dumps(h).encode() if not isinstance(h, bytes) else h
    t = locked.with_name("x.skull")
    t.write_bytes(raw[:8] + struct.pack(">I", len(nh)) + nh + raw[12 + n:])
    return t


@pytest.mark.parametrize("change", [
    lambda h: {**h, "kdf": {**h["kdf"], "mem": 2 ** 40}},
    lambda h: {**h, "kdf": {**h["kdf"], "ops": 10 ** 6}},
    lambda h: {**h, "chunk": 10 ** 12},
    lambda h: {**h, "keys": h["keys"] * 2000},
    lambda h: {**h, "v": 2},
    lambda h: {**h, "alg": "rot13"},
    lambda h: [1, 2, 3],
    lambda h: "a string",
    lambda h: b"[" * 50000 + b"]" * 50000,
])
def test_5_14_a_crafted_header_is_refused_fast(tmp_path, change):
    t = _with_header(_lock(tmp_path), change)
    start = time.time()
    with pytest.raises(L.LockError):
        L.unlock(t, PW, remove_locked=False)
    assert time.time() - start < 2


def test_6_the_same_password_typed_as_nfc_or_nfd_opens_the_file(tmp_path):
    pw = "पासवर्ड café secret"
    locked = _lock(tmp_path, pw=unicodedata.normalize("NFC", pw))
    assert L.unlock(locked, unicodedata.normalize("NFD", pw)).read_bytes() == b"secret data"


@pytest.mark.parametrize("bad, expect", [
    ("CON", "unlocked"), ("nul.txt", "unlocked.txt"), ("a:b.txt", "ab.txt"), ("..", "unlocked"), ("", "unlocked"),
    ("invoice‮fdp.exe", "invoicefdp.exe"), ("report.pdf   ", "report.pdf"), ("x" * 500 + ".txt", None),
])
def test_9_restored_names_are_made_safe(bad, expect):
    n, warn = L.safe_name(bad)
    assert "‮" not in n and ":" not in n and len(n) <= 200
    if expect:
        assert n == expect
    if n.endswith(".exe"):
        assert "program" in warn


def test_11_a_file_appearing_at_the_destination_is_never_overwritten(tmp_path):
    locked = _lock(tmp_path)
    (tmp_path / "a.txt").write_text("someone else's file")
    (tmp_path / "a.unlocking.tmp").write_text("an unrelated file with the old temp name")
    back = L.unlock(locked, PW)
    assert back.name == "a (1).txt" and (tmp_path / "a.txt").read_text() == "someone else's file"
    assert (tmp_path / "a.unlocking.tmp").read_text().startswith("an unrelated")


def test_12_hard_linked_files_are_refused(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("shared")
    try:
        os.link(f, tmp_path / "b.txt")
    except OSError:
        pytest.skip("no hard links on this file system")
    with pytest.raises(L.LockError, match="hard links"):
        L.lock(f, PW, **FAST)
    assert (tmp_path / "b.txt").read_text() == "shared"


def test_16_damaged_content_says_damaged_not_wrong_password(tmp_path):
    locked = _lock(tmp_path, data=os.urandom(2 * L.CHUNK))
    raw = bytearray(locked.read_bytes())
    raw[-100] ^= 1
    locked.write_bytes(bytes(raw))
    with pytest.raises(L.LockError, match="damaged"):
        L.unlock(locked, PW, remove_locked=False)


def test_17_recovery_keys_ignore_spaces_and_case_and_bad_ones_are_refused(tmp_path):
    rk = L.new_recovery_key()
    locked = _lock(tmp_path, rk=rk)
    spaced = " ".join(rk.upper()[i:i + 8] for i in range(0, 64, 8))
    assert L.unlock(locked, recovery_key=spaced, remove_locked=False).read_bytes() == b"secret data"
    with pytest.raises(L.LockError):
        _lock(tmp_path, name="b.txt", rk="not-a-key")


def test_stream_attacks_cut_at_a_chunk_boundary_reorder_and_splice(tmp_path):
    data = os.urandom(3 * L.CHUNK)
    a = _lock(tmp_path, data=data, name="a.bin")
    raw = a.read_bytes()
    n = struct.unpack(">I", raw[8:12])[0]
    head = 12 + n + 24
    body = raw[head:]
    size = L.CHUNK + L.ABYTES
    chunks = [body[i:i + size] for i in range(0, len(body), size)]
    variants = {"last chunk dropped": head and raw[:head] + b"".join(chunks[:-1]),
                "middle swapped": raw[:head] + chunks[0] + chunks[2] + chunks[1] + b"".join(chunks[3:]),
                "middle duplicated": raw[:head] + chunks[0] + chunks[1] + chunks[1] + b"".join(chunks[2:])}
    b = _lock(tmp_path, data=os.urandom(3 * L.CHUNK), name="b.bin")
    rb = b.read_bytes()
    nb_ = struct.unpack(">I", rb[8:12])[0]
    variants["header of B on stream of A"] = rb[:12 + nb_ + 24] + body
    for what, blob in variants.items():
        t = tmp_path / "t.skull"
        t.write_bytes(blob)
        with pytest.raises(L.LockError):
            L.unlock(t, PW, remove_locked=False)
        assert not list(tmp_path.glob("a.bin")), what


def test_flipping_every_byte_of_a_two_chunk_file_is_caught(tmp_path):
    locked = _lock(tmp_path, data=os.urandom(L.CHUNK + 300))
    raw = locked.read_bytes()
    t = tmp_path / "t.skull"
    for i in range(0, len(raw), max(1, len(raw) // 400)):
        b = bytearray(raw)
        b[i] ^= 0x01
        t.write_bytes(bytes(b))
        with pytest.raises(L.LockError):
            L.unlock(t, PW, remove_locked=False)
