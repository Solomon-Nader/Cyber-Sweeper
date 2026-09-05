"""Allow ``python -m cybersweep`` to behave like the ``cybersweep`` command."""

from cybersweep.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
