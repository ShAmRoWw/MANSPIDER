"""MANSPIDER package bootstrap."""

import sys

# Parsing imports a broad dependency tree.  Suppress opportunistic bytecode
# cache writes so an installation or plugin path mounted from customer storage
# is never modified merely because the scanner imported a module.  The package
# launcher itself should still be installed on local/read-only storage because
# Python resolves this first module before this assignment can take effect.
sys.dont_write_bytecode = True
