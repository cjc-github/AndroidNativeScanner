"""Allow ``python -m soinsight`` execution."""

from .cli.main import main

raise SystemExit(main())
