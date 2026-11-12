"""10 Nov 2026: the SKULL.ORG file locker prototype - round trips, wrong keys, tampering, truncation, odd names, safety."""
import os
import secrets

import pytest

from skull_locker import locker as L

FAST = {"ops": 2, "mem": 8 * 1024 * 1024}


@pytest.fixture(autouse=True)
def _fast_kdf(monkeypatch):
    monkeypatch.setattr(L, "ALLOW_WEAK_KDF", True)          # light Argon2 for the test suite only
          # tests only: lighter Argon2id so 100+ cases run quickly


def _lock(p, pw="correct horse battery", rk=None):
    return L.lock(p, pw, rk, **FAST)


@pytest.mark.parametrize("size", [0, 1, L.CHUNK - 1, L.CHUNK, L.CHUNK + 1, 3 * L.CHUNK + 17])
def test_round_trip_every_size_and_the_original_is_gone(tmp_path, size):
    data = secrets.token_bytes(size)
    f = tmp_path / "report.pdf"
    f.write_bytes(data)
    locked = _lock(f)
    assert not f.exists() and locked.suffix == ".skull" and "report" not in locked.name    # the name is hidden too
    back = L.unlock(locked, "correct horse battery")
    assert back.name == "report.pdf" and back.read_bytes() == data and not locked.exists()


def test_wrong_password_and_recovery_key(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("secret")
    rk = L.new_recovery_key()
    locked = _lock(f, rk=rk)
    with pytest.raises(L.LockError):
        L.unlock(locked, "wrong password!!", remove_locked=False)
    with pytest.raises(L.LockError):
        L.unlock(locked, recovery_key=L.new_recovery_key(), remove_locked=False)
    assert locked.exists() and not list(tmp_path.glob("*.tmp"))                # nothing half-written is left
    assert L.unlock(locked, recovery_key=rk).read_text() == "secret"            # the recovery key opens it


def test_every_changed_byte_is_caught(tmp_path):
    f = tmp_path / "b.bin"
    f.write_bytes(secrets.token_bytes(300))
    locked = _lock(f)
    raw = locked.read_bytes()
    for i in range(0, len(raw), 7):                                          # flip one byte at a time
        bad = bytearray(raw)
        bad[i] ^= 0x01
        t = tmp_path / f"t{i}.skull"
        t.write_bytes(bytes(bad))
        with pytest.raises(L.LockError):
            L.unlock(t, "correct horse battery", remove_locked=False)
    assert not list(tmp_path.glob(".unlocking-*.tmp")) and not list(tmp_path.glob(".skull-*.tmp"))


def test_truncated_and_extended_files_are_caught(tmp_path):
    f = tmp_path / "c.bin"
    f.write_bytes(secrets.token_bytes(2 * L.CHUNK + 5))
    locked = _lock(f)
    raw = locked.read_bytes()
    for cut in (len(raw) - 1, len(raw) - (L.CHUNK // 2), 40, 9):
        t = tmp_path / f"cut{cut}.skull"
        t.write_bytes(raw[:cut])
        with pytest.raises(L.LockError):
            L.unlock(t, "correct horse battery", remove_locked=False)
    t = tmp_path / "longer.skull"
    t.write_bytes(raw + b"extra")
    with pytest.raises(L.LockError):
        L.unlock(t, "correct horse battery", remove_locked=False)
    nf = tmp_path / "plain.skull"
    nf.write_bytes(b"not a locked file at all")
    with pytest.raises(L.LockError):
        L.unlock(nf, "x" * 10, remove_locked=False)


def test_hindi_and_unusual_names_and_no_overwrite(tmp_path):
    f = tmp_path / "रिपोर्ट नवंबर 2026 (final).xlsx"
    f.write_bytes(b"data")
    locked = _lock(f)
    (tmp_path / f.name).write_bytes(b"a newer file with the same name")       # never overwritten on unlock
    back = L.unlock(locked, "correct horse battery")
    assert back.name == "रिपोर्ट नवंबर 2026 (final) (1).xlsx" and back.read_bytes() == b"data"
    assert (tmp_path / f.name).read_bytes() == b"a newer file with the same name"


def test_short_passwords_are_refused_and_a_failed_lock_keeps_the_original(tmp_path, monkeypatch):
    f = tmp_path / "d.txt"
    f.write_text("keep me")
    with pytest.raises(L.LockError):
        L.lock(f, "short", **FAST)

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(L, "_decrypt_to", boom)                               # the verify step fails mid-lock
    with pytest.raises(OSError):
        _lock(f)
    assert f.read_text() == "keep me" and not list(tmp_path.glob("*.skull*"))


def test_many_random_round_trips(tmp_path):
    for i in range(60):
        data = os.urandom(secrets.randbelow(5 * L.CHUNK))
        f = tmp_path / f"f{i}.dat"
        f.write_bytes(data)
        pw = secrets.token_urlsafe(12)
        assert L.unlock(_lock(f, pw), pw).read_bytes() == data


def test_the_right_click_entries_and_the_command_line(tmp_path, monkeypatch, capsys):
    from skull_locker import __main__ as M
    e = M.menu_entries(python="C:/py/pythonw.exe")
    assert e[M.MENU_LOCK][0] == "Lock with SKULL" and " gui-lock " in e[M.MENU_LOCK][1] and e[M.MENU_LOCK][1].endswith('"%1"')
    assert e[M.MENU_UNLOCK][0] == "Unlock with SKULL" and M.MENU_UNLOCK.endswith(r".skull\shell\SkullUnlock")
    assert all(k.startswith(r"Software\Classes") for k in e)              # this user only, no admin
    f = tmp_path / "notes.txt"
    f.write_text("hello")
    answers = iter(["a long passphrase", "a long passphrase"])
    monkeypatch.setattr(M.getpass, "getpass", lambda prompt="": next(answers))
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    real_lock = L.lock
    monkeypatch.setattr(M.L, "lock", lambda p, pw, rk: real_lock(p, pw, rk, **FAST))
    assert M.main(["lock", str(f)]) == 0 and not f.exists()
    locked = next(tmp_path.glob("*.skull"))
    monkeypatch.setattr(M.getpass, "getpass", lambda prompt="": "a long passphrase")
    assert M.main(["unlock", str(locked)]) == 0 and (tmp_path / "notes.txt").read_text() == "hello"
