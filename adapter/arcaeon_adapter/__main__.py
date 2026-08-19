# SPDX-License-Identifier: MIT
"""`python -m arcaeon_adapter` == `python -m arcaeon_adapter.proxy`.

The shorter form is what goes in an MCP client config, where the line is already
long enough. Both spellings are supported forever; config files outlive advice.
"""
import sys

from .proxy import main

if __name__ == "__main__":
    sys.exit(main())
