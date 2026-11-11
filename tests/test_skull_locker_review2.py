"""10 Nov 2026: the fixes for Claude Opus's SECOND review of the SKULL locker, one test each (finding numbers)."""
import os
import subprocess
import sys

import pytest

from skull_locker import locker as L

PW = "correct horse battery"


def test_4_lock_refuses_weak_key_settings_and_works_with_the_real_ones(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    with pytest.raises(L.LockError, match="weaker"):
        L.lock(f, PW, ops=1, mem=8 * 1024 * 1024)
    assert f.read_text() == "x"
    out = L.lock(f, PW)                                                   # the real defaults: 3 passes, 64 MiB
    assert L.unlock(out, PW).read_text() == "x"


def test_4_a_received_file_asking_for_huge_settings_is_refused(tmp_path, monkeypatch):
    import json
    import struct
    monkeypatch.setattr(L, "ALLOW_WEAK_KDF", True)
    f = tmp_path / "a.txt"
    f.write_text("x")
    out = L.lock(f, PW, ops=1, mem=8 * 1024 * 1024)
    raw = out.read_bytes()
    n = struct.unpack(">I", raw[8:12])[0]
    h = json.loads(raw[12:12 + n])
    for change in ({"mem": 1024 ** 3}, {"ops": 20}):
        nh = json.dumps({**h, "kdf": {**h["kdf"], **change}}).encode()
        t = tmp_path / "t.skull"
        t.write_bytes(raw[:8] + struct.pack(">I", len(nh)) + nh + raw[12 + n:])
        with pytest.raises(L.Damaged):
            L.unlock(t, PW, remove_locked=False)


def test_9_wrong_secret_and_damage_are_told_apart(tmp_path, monkeypatch):
    monkeypatch.setattr(L, "ALLOW_WEAK_KDF", True)
    f = tmp_path / "a.txt"
    f.write_bytes(os.urandom(L.CHUNK * 2))
    out = L.lock(f, PW, ops=1, mem=8 * 1024 * 1024)
    with pytest.raises(L.WrongSecret):
        L.unlock(out, "not the password", remove_locked=False)
    cut = tmp_path / "cut.skull"
    cut.write_bytes(out.read_bytes()[:-(L.CHUNK // 2)])
    with pytest.raises(L.Damaged):
        L.unlock(cut, PW, remove_locked=False)


def test_1_unlock_claims_its_name_atomically_even_without_hard_links(tmp_path, monkeypatch):
    monkeypatch.setattr(L, "ALLOW_WEAK_KDF", True)
    f = tmp_path / "a.txt"
    f.write_text("mine")
    out = L.lock(f, PW, ops=1, mem=8 * 1024 * 1024)
    monkeypatch.setattr(os, "link", lambda *a, **k: (_ for _ in ()).throw(OSError("no hard links on FAT")))
    real_open = os.open

    def racing_open(path, flags, *a):
        if str(path).endswith("a.txt") and not os.path.exists(path):
            with open(path, "w") as h:                                     # someone creates it in the gap
                h.write("someone else's")
        return real_open(path, flags, *a)
    monkeypatch.setattr(os, "open", racing_open)
    back = L.unlock(out, PW)
    assert (tmp_path / "a.txt").read_text() == "someone else's" and back.name == "a (1).txt" and back.read_text() == "mine"


def test_2_17_names_are_checked_after_cutting_and_cleaning():
    for bad in ("x" * 300 + ".exe.", "y" * 300 + ".exe ", "a​b.EXE", "setup.iso", "invoice‮fdp.exe"):
        n, warn = L.safe_name(bad)
        assert len(n) <= 200 and not n.endswith((".", " ")) and warn, bad
    assert L.safe_name("CONIN$")[0] == "unlocked" and L.safe_name("nul .txt")[0] == "unlocked.txt"
    assert L.safe_name("a﻿b؜.txt")[0] == "ab.txt"


def test_13_whitespace_passwords_are_refused(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    for pw in (" " * 12, "", "   short "):
        with pytest.raises(L.LockError):
            L.lock(f, pw)


def test_10_only_the_one_format_is_accepted(tmp_path, monkeypatch):
    import json
    import struct
    monkeypatch.setattr(L, "ALLOW_WEAK_KDF", True)
    f = tmp_path / "a.txt"
    f.write_text("x")
    out = L.lock(f, PW, ops=1, mem=8 * 1024 * 1024)
    raw = out.read_bytes()
    n = struct.unpack(">I", raw[8:12])[0]
    for change in ({"subkeys": False}, {"norm": "NFD"}):
        nh = json.dumps({**json.loads(raw[12:12 + n]), **change}).encode()
        t = tmp_path / "t.skull"
        t.write_bytes(raw[:8] + struct.pack(">I", len(nh)) + nh + raw[12 + n:])
        with pytest.raises(L.Damaged):
            L.unlock(t, PW, remove_locked=False)


def test_7_the_menu_command_works_from_a_folder_whose_name_has_a_quote(tmp_path):
    from skull_locker import __main__ as M
    odd = tmp_path / "O'Brien files"
    odd.mkdir()
    (odd / "json.py").write_text(f"open(r'{tmp_path / 'PWNED'}', 'w')\n")
    victim = odd / "notes.txt"
    victim.write_text("hi")
    M.write_launcher()
    cmd = M.menu_entries(sys.executable)[M.MENU_UNLOCK][1].replace("gui-unlock", "help").replace('"%1"', f'"{victim}"')
    r = subprocess.run(cmd, shell=True, cwd=str(odd), capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "PWNED").exists()


def test_6_the_error_log_never_holds_a_file_name(tmp_path, monkeypatch):
    from skull_locker import __main__ as M
    import types
    monkeypatch.setattr(M.Path, "home", classmethod(lambda cls: tmp_path))
    shown = []
    tk = types.SimpleNamespace(Tk=lambda: types.SimpleNamespace(withdraw=lambda: None, destroy=lambda: None))
    mb = types.SimpleNamespace(showerror=lambda t, m: shown.append(m), showinfo=lambda *a: None, askyesno=lambda *a: False)
    sd = types.SimpleNamespace(askstring=lambda *a, **k: PW)
    monkeypatch.setitem(sys.modules, "tkinter", tk)
    monkeypatch.setitem(sys.modules, "tkinter.messagebox", mb)
    monkeypatch.setitem(sys.modules, "tkinter.simpledialog", sd)
    tk.messagebox, tk.simpledialog = mb, sd
    secret_name = tmp_path / "salary-of-ravi.xlsx"
    secret_name.write_text("x")
    monkeypatch.setattr(M.L, "lock", lambda *a, **k: (_ for _ in ()).throw(OSError(f"disk error at {secret_name}")))
    assert M._gui(str(secret_name), "lock") == 1
    log = (tmp_path / "skull_locker_error.log").read_text()
    assert "OSError" in log and "salary" not in log
    assert "still there" in shown[0]
