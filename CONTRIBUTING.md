# Contributing

Thank you for helping. The most useful contributions, in order:

1. **A failing test.** Found a case the locker gets wrong? A test in `tests/` that shows it is the best bug report.
2. **A review.** Read `skull_locker/locker.py` and `docs/design.md` and open an issue for anything that looks wrong.
   The three earlier reviews and their fixes are in `docs/reviews/`.
3. **Platform checks.** Results from the right-click menu on your Windows version, or from macOS and Linux.

Before a pull request:

```console
python -m pip install -e ".[test]"
python -m pytest -q
python tests/stress.py --quick
```

Rules for changes to the cryptography: only libsodium primitives through PyNaCl, never our own constructions; the
known-answer file `tests/data/skull_v1_sample.skull` must still open; a format change needs a new version number in
the header and a way to open the old files.
