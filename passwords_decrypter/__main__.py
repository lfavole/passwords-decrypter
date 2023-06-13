"""
Passwords decrypter.
"""

import sys

if __package__ is None and not hasattr(sys, "frozen"):
    # direct call of __main__.py
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from passwords_decrypter import main  # pylint: disable=C0413

if __name__ == "__main__":
    main()
