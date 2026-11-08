@echo off
title Gmail Spam Deleter
cd /d "%~dp0"
echo Starting Gmail Spam Deleter Web App...
start "" ".\.venv\Scripts\python.exe" -m streamlit run src/web/app.py --server.port 8501 --server.headless false --browser.gatherUsageStats false
timeout /t 2 /nobreak >nul
start "" "http://localhost:8501"
exit
