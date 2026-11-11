"""skull-locker - lock any file with a password.

    skull lock FILE            asks for the password twice (and offers a recovery key)
    skull unlock FILE.skull    asks for the password (or the recovery key)
    skull install-menu         Windows: "Lock with SKULL" / "Unlock with SKULL" in the right-click menu
                               (this user only, no admin rights; Python 3.11+)
    skull remove-menu          remove those entries again
    skull gui-lock FILE        the small password window (what the right-click runs)
    skull gui-unlock FILE

Design, format and reviews: https://github.com/skull-org/skull-locker
"""
from __future__ import annotations

import getpass
import secrets
import sys
from pathlib import Path

from skull_locker import locker as L

MENU_LOCK = r"Software\Classes\*\shell\SkullLock"
MENU_UNLOCK = r"Software\Classes\SystemFileAssociations\.skull\shell\SkullUnlock"
NOT_FOREVER = ("Older copies of the original may still exist in backups, cloud version history (OneDrive, Dropbox), "
               "Windows shadow copies or on an SSD - lock a file BEFORE it goes into a synced folder.")   # review 2 #3
MIN_PY = (3, 11)                                                                                  # review 2 #7


def menu_entries(python: str | None = None) -> dict:
    """{registry key: (label, command)} - pure, so it is testable without touching the registry.

    -P (Python 3.11+) keeps the clicked file's folder off the import path, so a planted skull_locker/ or json.py there
    can never run (-I would also hide the user's installed crypto library); -E ignores PYTHON* variables. The locker is
    loaded from ITS OWN folder by an absolute path, written with repr() so any folder name is exact (review 2 #7)."""
    if python:
        py = python
    else:
        exe = Path(sys.executable)
        w = exe.with_name("pythonw.exe")
        py = str(w if w.exists() else exe)
    launcher = launcher_path()

    def cmd(verb: str) -> str:              # review 3 #3: no code on the command line, so no quoting to break
        return f'"{py}" -P -E "{launcher}" {verb} "%1"'
    return {MENU_LOCK: ("Lock with SKULL", cmd("gui-lock")), MENU_UNLOCK: ("Unlock with SKULL", cmd("gui-unlock"))}


def launcher_path() -> Path:
    return Path(__file__).resolve().parent / "skull_launch.pyw"


def write_launcher() -> Path:
    """A fixed launcher next to the package: it puts the package's own folder (absolute) first and runs main()."""
    home = str(Path(__file__).resolve().parents[1])
    p = launcher_path()
    p.write_text("import sys\n"
                 f"sys.path.insert(0, {home!r})\n"
                 "from skull_locker.__main__ import main\n"
                 "sys.exit(main(sys.argv[1:]))\n", encoding="utf-8")
    return p


def install_menu() -> str:
    if sys.version_info < MIN_PY:                                                                 # review 2 #7
        raise L.LockError("the right-click menu needs Python 3.11 or newer")
    import winreg
    write_launcher()
    for key, (label, cmd) in menu_entries().items():
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, label)
            if key == MENU_LOCK:                                                                  # review 2 #18
                winreg.SetValueEx(k, "AppliesTo", 0, winreg.REG_SZ, "NOT System.FileExtension:=.skull")
                winreg.SetValueEx(k, "MultiSelectModel", 0, winreg.REG_SZ, "Single")
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key + r"\command") as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, cmd)
    return "right-click menu installed (this user)"


def remove_menu() -> str:
    import winreg
    for key in menu_entries():
        for sub in (key + r"\command", key):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
            except OSError:
                pass
    return "right-click menu removed"


def confirm_group(rk: str) -> int:
    """Review 2 #12: which 8-character group of the recovery key the user must type back (a random one)."""
    return secrets.randbelow(8)


def _state(path: str, out: Path | None) -> str:
    """Review 2 #19: say what really exists now, not 'nothing is lost'."""
    p = Path(path)
    bits = [f"{p.name}: {'still there' if p.exists() else 'gone'}"]
    if out is not None:
        bits.append(f"{out.name}: {'there' if out.exists() else 'not made'}")
    return "; ".join(bits)


def _gui(path: str, mode: str) -> int:
    import tkinter as tk
    from tkinter import messagebox, simpledialog
    root = tk.Tk()
    root.withdraw()
    out = None
    try:
        if mode == "lock":
            pw = simpledialog.askstring("SKULL lock", f"Password for\n{Path(path).name}\n(8+ characters; a passphrase is best)", show="*")
            if not pw:
                return 1
            if L.password_problem(pw):                                   # review 3 #7: before any recovery key
                messagebox.showerror("SKULL lock", L.password_problem(pw) + " - nothing was locked.")
                return 1
            if simpledialog.askstring("SKULL lock", "Type the password again", show="*") != pw:
                messagebox.showerror("SKULL lock", "The two passwords are different - nothing was locked.")
                return 1
            rk = L.new_recovery_key() if messagebox.askyesno(
                "SKULL lock", "Also make a recovery key? (recommended - it opens the file if you forget the password)") else None
            if rk:
                # the key is shown BEFORE anything is locked and one RANDOM group must be typed back (review 1 #10, 2 #12)
                groups = [rk[i:i + 8] for i in range(0, 64, 8)]
                g = confirm_group(rk)
                messagebox.showinfo("SKULL recovery key", "WRITE THIS DOWN and keep it safe. It is shown only once:\n\n"
                                    + "  ".join(f"{i + 1}:{x}" for i, x in enumerate(groups))
                                    + "\n\nNext you will type one group back to show you have it.")
                back = simpledialog.askstring("SKULL recovery key", f"Type group {g + 1} of the recovery key") or ""
                if back.replace(" ", "").lower() != groups[g]:
                    messagebox.showerror("SKULL lock", "That does not match the recovery key - nothing was locked.")
                    return 1
            out = L.lock(path, pw, rk)
            del pw          # best effort only: Python cannot wipe a string from memory (said in the design doc)
            messagebox.showinfo("SKULL lock", f"Locked: {out.name}\nWithout the password (or the recovery key) this "
                                              f"locked file cannot be opened - not even by us.\n\n{NOT_FOREVER}")
        else:
            pw = simpledialog.askstring("SKULL unlock", f"Password (or recovery key) for\n{Path(path).name}", show="*")
            if not pw:
                return 1
            looks_like_key = len(pw.replace(" ", "").replace("-", "")) == 64
            try:
                out = L.unlock(path, password=pw)
            except L.WrongSecret:                                    # review 2 #9: only a wrong secret is retried
                if not looks_like_key:
                    raise
                out = L.unlock(path, recovery_key=pw)
            del pw
            warn = L.unlock.last_warning
            messagebox.showinfo("SKULL unlock", f"Unlocked: {out.name}" + (f"\n\nCareful: {warn}" if warn else ""))
        return 0
    except L.LockError as e:
        messagebox.showerror("SKULL", str(e))
        return 1
    except Exception as e:  # noqa: BLE001 - review 1 #8: under pythonw a crash would close the window silently
        log = Path.home() / "skull_locker_error.log"
        try:                       # review 2 #6: the KIND of error and where in OUR code - never a path or a name
            import traceback
            frames = [f"{Path(f.filename).name}:{f.lineno} {f.name}" for f in traceback.extract_tb(e.__traceback__)]
            log.write_text(f"{type(e).__name__}\n" + "\n".join(frames) + "\n", encoding="utf-8")
        except OSError:
            pass
        messagebox.showerror("SKULL", f"Something went wrong ({type(e).__name__}). Now: {_state(path, out)}.\n"
                                      f"Details for support (no file names): {log}")
        return 1
    finally:
        root.destroy()


def main(argv=None) -> int:
    a = list(sys.argv[1:] if argv is None else argv)
    if not a or a[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, rest = a[0], a[1:]
    if cmd == "install-menu":
        print(install_menu())
        return 0
    if cmd == "remove-menu":
        print(remove_menu())
        return 0
    if cmd in ("gui-lock", "gui-unlock") and rest:
        return _gui(rest[0], "lock" if cmd == "gui-lock" else "unlock")
    if cmd == "lock" and rest:
        pw = getpass.getpass("Password: ")
        if L.password_problem(pw):                                       # review 3 #7
            print(L.password_problem(pw) + " - nothing was locked.")
            return 1
        if getpass.getpass("Again: ") != pw:
            print("The two passwords are different - nothing was locked.")
            return 1
        rk = None
        if input("Make a recovery key? [Y/n] ").strip().lower() != "n":
            rk = L.new_recovery_key()                     # review 2 #12: shown and confirmed BEFORE anything is locked
            groups = [rk[i:i + 8] for i in range(0, 64, 8)]
            print("RECOVERY KEY - write it down, it is shown only once:\n  " + " ".join(groups))
            g = confirm_group(rk)
            if input(f"Type group {g + 1} of the key: ").replace(" ", "").lower() != groups[g]:
                print("That does not match - nothing was locked.")
                return 1
        out = L.lock(rest[0], pw, rk)
        print(f"locked -> {out}\n{NOT_FOREVER}")
        return 0
    if cmd == "unlock" and rest:
        secret = getpass.getpass("Password or recovery key: ")
        try:
            out = L.unlock(rest[0], password=secret)
        except L.WrongSecret:                                      # review 2 #9
            if len(secret.replace(" ", "").replace("-", "")) != 64:
                raise
            out = L.unlock(rest[0], recovery_key=secret)
        print(f"unlocked -> {out}" + (f"\nCareful: {L.unlock.last_warning}" if L.unlock.last_warning else ""))  # #8
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except L.LockError as e:
        print(f"SKULL: {e}")
        sys.exit(1)
