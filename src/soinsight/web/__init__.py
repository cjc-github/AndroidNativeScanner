"""The SOInsight web console.

The console is a local, loopback-only web interface: it drives the same
CLI the terminal uses and renders the results in the browser. It lives in the
package so that ``soinsight web`` and the ``web/server.py`` script run the
same code.
"""

from .console import main, run_console

__all__ = ["main", "run_console"]
