"""10 Nov 2026: the fixes for Claude Opus's THIRD review of the SKULL locker (finding numbers)."""
import hashlib
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from skull_locker import locker as L

PW = "correct horse battery"
SAMPLE = Path(__file__).parent / "data" / "skull_v1_sample.skull"


@pytest.fixture(autouse=True)
def _fast_kdf(monkeypatch):
    monkeypatch.setattr(L, "ALLOW_WEAK_KDF", True)


def _lock(tmp_path, data=b"x", name="a.txt"):
    f = tmp_path / name
    f.write_bytes(data)
    return L.lock(f, PW, ops=1, mem=8 * 1024 * 1024)


def test_5_the_format_never_changes_a_fixed_file_always_opens(tmp_path):
    """A .skull file made on 10 Nov 2026 (real settings) must open forever, by password and by recovery key."""
    for kw in ({"password": "known answer password 2026"},
               {"recovery_key": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}):
        t = tmp_path / "s.skull"
        t.write_bytes(SAMPLE.read_bytes())
        back = L.unlock(t, **kw)
        assert back.read_text(encoding="utf-8") == "SKULL format v1 known answer - do not change\n"
        back.unlink()


def test_5_subkeys_follow_the_libsodium_kdf_construction():
    """crypto_kdf_derive_from_key = BLAKE2b(key=master, salt=id (8 bytes LE) + 8 zero, person=ctx + 8 zero)."""
    master = bytes(range(32))
    for i, got in zip((1, 2), L._subkeys(master)):
        want = hashlib.blake2b(b"", digest_size=32, key=master, salt=struct.pack("<Q", i) + bytes(8),
                               person=b"SKULLkey" + bytes(8)).digest()
        assert got == want
    assert L._subkeys(master)[0] != L._subkeys(master)[1]


def test_3_the_menu_works_when_the_python_path_has_a_quote(tmp_path):
    from skull_locker import __main__ as M
    M.write_launcher()
    cmd = M.menu_entries(sys.executable)[M.MENU_LOCK][1]
    assert " -c " not in cmd and str(M.launcher_path()) in cmd
    odd = tmp_path / "O'Brien"
    odd.mkdir()
    victim = odd / "n.txt"
    victim.write_text("hi")
    r = subprocess.run(cmd.replace("gui-lock", "help").replace('"%1"', f'"{victim}"'), shell=True, cwd=str(odd),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr


def test_7_8_the_password_rule_counts_only_real_characters():
    assert L.password_problem("a      b")
    assert L.password_problem("        ")
    assert not L.password_problem("four word pass phrase")


def test_7_lock_refuses_settings_it_could_not_open_again(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    with pytest.raises(L.LockError, match="outside"):
        L.lock(f, PW, ops=20, mem=8 * 1024 * 1024)
    assert f.read_text() == "x"


def test_9_a_file_changed_during_lock_leaves_no_locked_copy(tmp_path, monkeypatch):
    f = tmp_path / "live.log"
    f.write_text("one\n")
    real = L._decrypt_to

    def append_then(*a, **k):
        with open(f, "a") as h:
            h.write("two\n")
        return real(*a, **k)
    monkeypatch.setattr(L, "_decrypt_to", append_then)
    with pytest.raises(L.LockError, match="nothing was locked"):
        L.lock(f, PW, ops=1, mem=8 * 1024 * 1024)
    assert not list(tmp_path.glob("*.skull")) and "two" in f.read_text()


def test_11_long_hindi_names_fit_in_255_bytes_everywhere():
    n, _ = L.safe_name("बहुत" * 80 + ".pdf")
    assert len(n.encode("utf-8")) <= 200 and n.endswith(".pdf")


def test_15_a_failed_rename_leaves_no_empty_placeholder(tmp_path, monkeypatch):
    out = _lock(tmp_path, b"data")
    real = os.replace

    def fail(a, b):
        if str(b).endswith("a.txt"):
            raise OSError("disk full")
        return real(a, b)
    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError):
        L.unlock(out, PW, remove_locked=False)
    assert not (tmp_path / "a.txt").exists() and out.exists()


def test_2_stale_plaintext_temp_files_are_removed_later(tmp_path):
    old = tmp_path / ".unlocking-abc.tmp"
    old.write_text("plaintext left by a crash")
    fresh = tmp_path / ".unlocking-new.tmp"
    fresh.write_text("another unlock still running")
    past = time.time() - 2 * L.STALE_SECONDS
    os.utime(old, (past, past))
    _lock(tmp_path)                                    # any SKULL run in the folder cleans up
    assert not old.exists() and fresh.exists()


def test_4_more_active_file_types_are_flagged():
    for ext in (".html", ".svg", ".xll", ".one", ".appref-ms", ".inf", ".settingcontent-ms"):
        assert L.safe_name("x" + ext)[1], ext
