"""Root entrypoint for Streamlit Community Cloud (standard convention).
Redirects to src/web/app.py.
"""
import sys
import runpy
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Launch main web app
target_script = ROOT_DIR / "src" / "web" / "app.py"
runpy.run_path(str(target_script), run_name="__main__")
