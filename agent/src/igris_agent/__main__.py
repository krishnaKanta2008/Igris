"""Entry point for `python -m igris_agent` and the `igris-agent` script."""

from igris_agent import __version__


def main() -> int:
    print(f"igris-agent {__version__} (Phase 0 scaffold)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
