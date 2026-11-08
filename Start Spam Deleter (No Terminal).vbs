' Silent background launcher for Gmail Spam Deleter
' Runs the app in the background with ZERO terminal windows visible!
Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
currentDir = fso.GetParentFolderName(WScript.ScriptFullName)

' Run Streamlit silently via python venv
cmd = "cmd /c cd /d """ & currentDir & """ && .\.venv\Scripts\python.exe -m streamlit run src/web/app.py --server.port 8501 --server.headless false --browser.gatherUsageStats false"
WshShell.Run cmd, 0, False

' Give server 2 seconds to bind port and open browser
WScript.Sleep 2000
WshShell.Run "http://localhost:8501"

