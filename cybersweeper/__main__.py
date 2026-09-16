# Allow python -m cybersweeper to behave like the cybersweeper command.

from cybersweeper.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
