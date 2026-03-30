"""Shared fixtures and path setup for Phantom v3 tests."""

import os
import sys

# Ensure the project root is on sys.path so `agent.*` imports work.
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
