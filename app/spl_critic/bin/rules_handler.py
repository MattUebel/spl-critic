"""restmap.conf entry point for the rules endpoint.

Splunk executes scripts in bin/ as plain files, so we put the vendored
lib/ directory on sys.path before importing the real handler.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from spl_critic_app.rules_api import RulesHandler  # noqa: E402, F401
