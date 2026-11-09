"""Entry point for the SOInsight web console.

The console itself lives in :mod:`soinsight.web.console`, so the command
line (``soinsight web``) and this script run exactly the same code. This
file stays because ``start.sh`` and the Windows scripts call it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from soinsight.web.console import main

if __name__ == "__main__":
    raise SystemExit(main())
