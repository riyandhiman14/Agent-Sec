"""
agsec + Claude Code — setup firewall in 30 seconds.

Run this script or use the CLI commands below.
"""

import subprocess
import sys

print("""
=== agsec Claude Code Setup ===

Three commands to protect your agent:

  1. pip install agsec
  2. agsec init
  3. agsec install claude-code

That's it. The firewall is active.

--- What gets blocked by default ---

  rm -rf /                    BLOCKED (file deletion)
  cat .env                    BLOCKED (secret access)
  git push --force            BLOCKED (force push)
  git push origin main        BLOCKED (protected branch)
  curl --data secrets.json    BLOCKED (data exfiltration)

--- What gets allowed ---

  ls, grep, find              ALLOWED (read ops)
  python -m pytest            ALLOWED (safe bash)
  git push origin feature/x   ALLOWED (feature branch)

--- Manage policies ---

  agsec policy list           # see all rules
  agsec policy add            # add a rule (interactive)
  agsec policy remove <sid>   # remove a rule
  agsec validate              # check for errors
  agsec audit --stats         # view activity
""")
