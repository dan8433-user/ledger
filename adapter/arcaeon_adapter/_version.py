# SPDX-License-Identifier: MIT
"""One place the version lives.

`__init__.py` and `proxy.py` both need it, and `__init__.py` deliberately does NOT
import `proxy` (see the note there about the runpy warning landing in a customer's
stderr). Two hardcoded copies would drift, and the version is stamped into every
row as `seam_impl` — a row that lies about which build wrote it is a small
corruption of exactly the thing this package sells.
"""
VERSION = "0.1.0"
IMPL = f"arcaeon-adapter/{VERSION}"
