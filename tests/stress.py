"""skull-locker stress test - round trips, fuzzing, crash injection, a big file and the known-answer file.

    python tests/stress.py [--quick]      -> JSON summary on stdout, exit 0 when every check passed

1. ROUND TRIPS   1,000 random files (0 bytes to ~3 chunks, random names incl. Hindi), lock -> unlock -> identical
2. FUZZ          2,000 corrupted locked files (random byte flips, cuts, inserted bytes, random headers): every one
                 must fail with a LockError - never another exception, never a wrong file written out
3. CRASH         20 locks killed at a random moment in a child process: afterwards the original OR a complete,
                 openable locked copy always exists (never neither)
4. BIG FILE      a 256 MB file locked and unlocked with peak memory well under the file size (chunked)
5. KNOWN ANSWER  the sample file tests/data/skull_v1_sample.skull opens with its password and recovery key
Light Argon2 settings are used for 1-3 (the format is the same); 4-5 use the real defaults.
"""
from __future__ import annotations

import json
import os
import random
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skull_locker import locker as L  # noqa: E402

FAST = {"ops": 1, "mem": 8 * 1024 * 1024}
PW = "correct horse battery staple"
NAMES = ["a.txt", "रिपोर्ट.pdf", "space name.docx", "UPPER.XLSX", "dots.in.name.csv", "emoji-🔒.md", "x" * 120 + ".bin"]



def _python() -> str:
    """11 Nov 2026: never sys.executable for a child - under pythonw.exe it has no stdout and its pipe blocks forever."""
    try:
        from office.scheduler import console_python
        return console_python()
    except Exception:  # noqa: BLE001
        return sys.executable

def round_trips(n: int, d: Path) -> dict:
    bad = 0
    for i in range(n):
        data = os.urandom(random.choice([0, 1, 17, L.CHUNK - 1, L.CHUNK, L.CHUNK + 1, random.randrange(3 * L.CHUNK)]))
        f = d / f"{i}-{random.choice(NAMES)}"
        f.write_bytes(data)
        rk = L.new_recovery_key() if i % 3 == 0 else None
        out = L.lock(f, PW, rk, **FAST)
        back = L.unlock(out, PW if i % 2 == 0 or not rk else None, None if i % 2 == 0 or not rk else rk)
        if back.read_bytes() != data:
            bad += 1
        back.unlink()
    return {"n": n, "failed": bad}


def fuzz(n: int, d: Path) -> dict:
    src = d / "fuzz-src.bin"
    src.write_bytes(os.urandom(2 * L.CHUNK + 333))
    good = L.lock(src, PW, **FAST).read_bytes()
    wrong_kind, wrote, ok = 0, 0, 0
    for i in range(n):
        b = bytearray(good)
        how = i % 4
        if how == 0:
            for _ in range(random.randint(1, 4)):
                b[random.randrange(len(b))] ^= 1 << random.randrange(8)
        elif how == 1:
            b = b[:random.randrange(len(b))]
        elif how == 2:
            p = random.randrange(len(b))
            b = b[:p] + os.urandom(random.randint(1, 64)) + b[p:]
        else:
            hdr = json.dumps({"v": 1, "x": secrets.token_hex(random.randint(1, 40)),
                              "kdf": {"ops": random.randint(-5, 99), "mem": random.randint(-1, 2 ** 41)}}).encode()
            b = bytearray(L.MAGIC + len(hdr).to_bytes(4, "big") + hdr + bytes(good[-500:]))
        t = d / f"fz{i}.skull"
        t.write_bytes(bytes(b))
        before = set(os.listdir(d))
        try:
            L.unlock(t, PW, remove_locked=False)
            wrote += 1                                   # a corrupted file must never unlock
        except L.LockError:
            ok += 1
        except Exception:  # noqa: BLE001
            wrong_kind += 1
        for extra in set(os.listdir(d)) - before:
            if not extra.endswith(".skull"):
                wrote += 1
                (d / extra).unlink(missing_ok=True)
        t.unlink(missing_ok=True)
    return {"n": n, "refused_cleanly": ok, "other_exception": wrong_kind, "wrote_output": wrote}


CHILD = r"""
import sys; sys.path.insert(0, {root!r})
from skull_locker import locker as L
L.ALLOW_WEAK_KDF = True
L.lock({path!r}, {pw!r}, ops=1, mem=8*1024*1024)
"""


def crash(n: int, d: Path) -> dict:
    lost = 0
    for i in range(n):
        sub = d / f"crash{i}"
        sub.mkdir()
        f = sub / "precious.bin"
        data = os.urandom(random.randint(1, 40) * L.CHUNK)
        f.write_bytes(data)
        p = subprocess.Popen([_python(), "-c", CHILD.format(root=str(ROOT), path=str(f), pw=PW)])
        time.sleep(random.uniform(0.0, 0.6))
        p.kill()
        p.wait()
        orig_ok = f.exists() and f.read_bytes() == data
        locked_ok = False
        for s in sub.glob("*.skull"):
            try:
                back = L.unlock(s, PW, out_dir=sub / "out" if (sub / "out").mkdir() or True else None, remove_locked=False)
                locked_ok = back.read_bytes() == data
            except L.LockError:
                pass
        if not (orig_ok or locked_ok):
            lost += 1
    return {"n": n, "both_lost": lost}


def big(d: Path, mb: int) -> dict:
    import tracemalloc
    f = d / "big.bin"
    with open(f, "wb") as h:
        for _ in range(mb):
            h.write(os.urandom(1024 * 1024))
    size = f.stat().st_size
    tracemalloc.start()
    t0 = time.time()
    out = L.lock(f, PW)
    back = L.unlock(out, PW)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    same = back.stat().st_size == size
    back.unlink()
    return {"mb": mb, "seconds": round(time.time() - t0, 1), "peak_python_mb": round(peak / 2 ** 20, 1),
            "same_size": same, "bounded": peak < size / 4}


def known_answer() -> dict:
    sample = Path(__file__).resolve().parent / "data" / "skull_v1_sample.skull"
    with tempfile.TemporaryDirectory() as td:
        ok = 0
        for kw in ({"password": "known answer password 2026"},
                   {"recovery_key": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}):
            t = Path(td) / "s.skull"
            t.write_bytes(sample.read_bytes())
            back = L.unlock(t, **kw)
            ok += back.read_text(encoding="utf-8") == "SKULL format v1 known answer - do not change\n"
            back.unlink()
    return {"opened": ok, "of": 2}


def main(quick: bool = False) -> dict:
    L.ALLOW_WEAK_KDF = True
    random.seed(20261110)
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        res = {"round_trips": round_trips(100 if quick else 1000, d / "rt" if (d / "rt").mkdir() or True else d),
               "fuzz": fuzz(200 if quick else 2000, d / "fz" if (d / "fz").mkdir() or True else d),
               "crash": crash(4 if quick else 20, d / "cr" if (d / "cr").mkdir() or True else d)}
        L.ALLOW_WEAK_KDF = False
        res["big_file"] = big(d / "bg" if (d / "bg").mkdir() or True else d, 32 if quick else 256)
        res["known_answer"] = known_answer()
    res["passed"] = (res["round_trips"]["failed"] == 0 and res["fuzz"]["other_exception"] == 0
                     and res["fuzz"]["wrote_output"] == 0 and res["crash"]["both_lost"] == 0
                     and res["big_file"]["same_size"] and res["big_file"]["bounded"]
                     and res["known_answer"]["opened"] == 2)
    return res


if __name__ == "__main__":
    r = main(quick="--quick" in sys.argv)
    print(json.dumps(r, indent=1))
    sys.exit(0 if r["passed"] else 1)
