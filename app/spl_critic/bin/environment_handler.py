"""restmap.conf entry point for the environment scan endpoint."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from spl_critic_app.environment_api import EnvironmentHandler  # noqa: E402, F401
