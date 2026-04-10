"""Allow running as `python -m cryptoguard` or `python -m cryptoguard.hook`."""

import sys

# If invoked as `python -m cryptoguard.hook`, the hook module's __main__
# block handles it. This file handles `python -m cryptoguard` for CLI.
if __name__ == "__main__":
    from .cli import main
    main()
