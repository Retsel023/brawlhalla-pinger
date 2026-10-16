@echo off
setlocal
cd /d "%~dp0"

py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if not errorlevel 1 (
    set "PINGER_PYTHON=py -3"
    goto run
)

python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if not errorlevel 1 (
    set "PINGER_PYTHON=python"
    goto run
)

echo Python 3.9 or newer was not found.
echo Install Python 3 from python.org, enable its launcher or PATH option,
echo then close and reopen this window and run start.bat again.
pause
exit /b 1

:run
%PINGER_PYTHON% "%~dp0pinger.py" %*
set "PINGER_EXIT=%ERRORLEVEL%"
if not "%PINGER_EXIT%"=="0" (
    echo.
    echo Brawlhalla Pinger stopped with an error. Check the message above.
    echo See README.md for setup and port troubleshooting.
    pause
)
exit /b %PINGER_EXIT%
