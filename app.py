"""Root entrypoint for Streamlit Community Cloud and Docker containers.
Redirects to src/web/app.py.
"""
import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Launch main web app
import src.web.app
