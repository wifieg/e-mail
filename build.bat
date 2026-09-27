@echo off
REM ====== بناء ملف تنفيذي واحد EmailManager.exe ======
REM يتطلب مرة واحدة:  pip install pyinstaller flask cryptography paramiko
cd /d "%~dp0"

python -m PyInstaller --noconfirm --clean --onefile --noconsole ^
  --name EmailManager ^
  --icon icon.ico ^
  --collect-submodules cryptography ^
  --collect-submodules paramiko ^
  --add-data "app.py;." ^
  --add-data "requirements.txt;." ^
  app.py

echo.
echo تم. الملف في:  dist\EmailManager.exe
pause
