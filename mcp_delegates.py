"""Launcher for the vsw delegate MCP server.

Resolves the repo from this file so it works regardless of process cwd.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from vsw.mcp_server import main

raise SystemExit(main())
