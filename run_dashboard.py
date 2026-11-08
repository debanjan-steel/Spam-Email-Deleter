"""Launcher for the Spam Email Deleter Web Dashboard.
Usage:
    python run_dashboard.py
"""
import sys
import subprocess
from pathlib import Path

def main():
    workspace = Path(__file__).resolve().parent
    app_path = workspace / "src" / "web" / "app.py"

    print("=" * 60)
    print("🛡️  Starting Gmail Spam Deleter Web Dashboard...")
    print(f"📂  Workspace: {workspace}")
    print("=" * 60)

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path),
        "--browser.gatherUsageStats=false",
        "--server.headless=false",
    ]
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n👋 Dashboard stopped.")

if __name__ == "__main__":
    main()

