"""restmap.conf entry point for the inference-cache endpoint."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from spl_critic_app.inference_api import InferenceHandler  # noqa: E402, F401
