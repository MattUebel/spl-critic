"""SPL Critic app runtime code.

This package is developed and tested with uv, then vendored into the
packaged Splunk app at ``spl_critic/lib/spl_critic_app/`` by the build
tool. Everything here must run on Splunk's bundled Python (3.9).
"""

from __future__ import annotations

try:
    # Written by the build tool when the app is packaged.
    from spl_critic_app._version import __version__
except ImportError:
    __version__ = "0.0.0+dev"

APP_NAME = "spl_critic"
