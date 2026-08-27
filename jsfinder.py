#!/usr/bin/env python3
"""JSFinder CLI executable script."""

import os
import sys

# Ensure package directory is on python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from jsfinder.cli import main

if __name__ == "__main__":
    sys.exit(main())
