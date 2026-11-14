import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
CORE = os.environ.get("TOROKA_CORE_PATH")
if not CORE:
    if (HERE.parent / "core").exists():
        CORE = str(HERE.parent / "core")
    elif (HERE.parent / "smart-scam-identifier" / "packages" / "core").exists():
        CORE = str(HERE.parent / "smart-scam-identifier" / "packages" / "core")
    else:
        CORE = str(HERE.parent / "core")

for p in (CORE, str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)
