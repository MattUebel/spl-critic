"""Import shims for running inside and outside of splunkd.

Splunk's Python SDK modules only exist when code runs under splunkd.
Tests and dev tooling import this module instead so the same handler
classes work in both environments.
"""

from __future__ import annotations

try:
    from splunk.persistconn.application import PersistentServerConnectionApplication

    HAS_SPLUNK = True
except ImportError:
    HAS_SPLUNK = False

    class PersistentServerConnectionApplication:  # type: ignore[no-redef]
        """Stand-in base class when the Splunk SDK is unavailable."""

        def __init__(self) -> None:
            pass
