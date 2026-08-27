# Contributing to RFIDeye

Thanks for wanting to help. This document is short, because most of it is one rule.

## The rule

**RFIDeye is read-only. Pull requests that add write, clone, restore, emulation, simulation, sniffing or key-recovery capability will be closed without merge.**

This is not a limitation waiting to be lifted. It is what makes the project defensible as an auditing tool, and it is enforced in code (`rfideye/read_only_guard.py`), in the test suite (`tests/test_read_only_guard.py`) and in a dedicated CI job.

Also out of scope:

* Key dictionaries or heuristics aimed at opening **third-party** systems. Supplying keys you already hold is supported; recovering keys you do not is not.
* Decoding stored-value, fare-history or personal data from transit and payment media.
* Anything whose primary use is duplicating a credential.

If you need those, the official Proxmark3 client already has them. Use it directly.

## What is very welcome

* New tag signatures and better output parsers — firmware revisions change the client's wording, and the parsers need to keep up.
* More accurate ATQA/SAK and transit-scheme mappings, ideally with a source.
* Fixes to autodetection on hardware or distributions we have not tested.
* Documentation, screenshots, translations.
* Tests. Always tests.

## Development setup

```bash
git clone https://github.com/yourname/rfideye.git
cd rfideye
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the suite and the linter before pushing:

```bash
pytest
ruff check .
```

You do **not** need a Proxmark3 to develop or to run the tests. Everything is driven through `DemoTransport` and canned client output in `rfideye/demo.py`; add fixtures there rather than requiring hardware.

## Coding standards

* Python 3.11+, type hints on every public function, Google-style docstrings.
* `ruff check .` must be clean. Line length 100.
* No new runtime dependency without a justification in the PR description **and** a comment in `pyproject.toml` explaining why the standard library is not enough.
* Keep modules focused. `read_only_guard.py` in particular must stay short enough to audit in one sitting.

## Touching the guard

Changes to `rfideye/read_only_guard.py` get extra scrutiny.

* Adding a rule to `ALLOWED_RULES` requires: a one-line justification in the PR, proof the command cannot modify a tag, and a test in `tests/test_read_only_guard.py`.
* Never widen `_SAFE_CHARS`. Shell metacharacters and quotes stay out.
* Never remove an entry from `FORBIDDEN_TOKENS` or `FORBIDDEN_SUBSTRINGS` to make a new rule fit. If a rule collides with the deny-list, the rule is wrong.
* The deny-list is intentionally redundant with the allow-list. Do not "simplify" it away.

## Reporting a security issue

If you find a way to make RFIDeye send a non-read-only command to the device, that is a security bug in the project's central claim. Please open an issue with the exact input, or contact the maintainers privately if you would rather not publish it first.

## Pull request checklist

- [ ] `pytest` passes.
- [ ] `ruff check .` is clean.
- [ ] New behaviour has tests.
- [ ] No write / clone / emulate / attack capability was added.
- [ ] Public functions have type hints and docstrings.
- [ ] `README.md` updated if user-facing behaviour changed.
