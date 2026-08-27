"""Allow ``python -m rfideye`` as an alternative entry point."""

from __future__ import annotations

from rfideye.cli import main

if __name__ == "__main__":  # pragma: no cover - trivial shim
    main()
