"""
MemGuard standalone entry point.
Run directly: python run.py
Or build with PyInstaller: pyinstaller memguard.spec
"""
import os
import sys
import time
import threading
import webbrowser
from pathlib import Path

# Ensure the package root is on sys.path when running as .exe
if getattr(sys, 'frozen', False):
    base = Path(sys.executable).parent
    sys.path.insert(0, str(base))
    # Point pydantic-settings to the bundled .env
    os.chdir(base)
else:
    base = Path(__file__).parent

import uvicorn
from MemGuard.config import settings
from MemGuard.gateway.proxy import app


def open_browser():
    time.sleep(2)
    webbrowser.open("http://localhost:8080/ui")


if __name__ == "__main__":
    print("=" * 56)
    print("  MemGuard — Agent Memory Protection Engine")
    print("  Dashboard: http://localhost:8080/ui")
    print("=" * 56)
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run(app, host="0.0.0.0", port=settings.gateway_port, log_level="info")
