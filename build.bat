@echo off
chcp 65001 >nul
echo ============================================
echo   MemGuard — Build .exe
echo ============================================

cd /d %~dp0

echo [1/3] Installing dependencies...
pip install -r MemGuard/requirements.txt

echo [2/3] Building with PyInstaller...
pyinstaller memguard.spec --clean --noconfirm

echo [3/3] Done!
echo Output: dist\MemGuard\MemGuard.exe
echo.
echo Double-click MemGuard.exe to launch.
echo Dashboard will open at http://localhost:8080/ui
pause
