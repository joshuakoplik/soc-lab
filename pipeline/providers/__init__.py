"""
Model backends behind pipeline.agent. See base.py for the contract every
backend implements and AGENT_BRIEF.md #4 for why this boundary exists: the
triage loop never imports a vendor SDK, only providers.base.Provider.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv  # noqa: E402

load_dotenv()
