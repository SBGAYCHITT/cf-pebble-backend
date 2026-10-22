@echo off
REM Pebble Launcher - backend smoke test. Double-click this file to run.
REM To test another backend:  smoke.bat https://example.pages.dev
REM
REM NOTE: keep this file ASCII-only. cmd reads .bat in the system ANSI code
REM page (GBK on zh-CN Windows); UTF-8 Chinese in here turns into garbage and
REM the garbled text gets parsed as commands. Chinese output comes from
REM smoke.mjs instead, which is fine once chcp 65001 is set.

chcp 65001 >nul
cd /d "%~dp0"

set "TARGET=https://cf-pebble-backend.pages.dev"
if not "%~1"=="" set "TARGET=%~1"

echo.
echo   Pebble Launcher backend check
echo   Target: %TARGET%
echo.

where node >nul 2>nul
if errorlevel 1 goto :nonode

node smoke.mjs "%TARGET%"
set "CODE=%errorlevel%"
goto :report

:nonode
echo   [STOP] node was not found in PATH.
echo          Install Node.js 18 or newer from https://nodejs.org , then run again.
set "CODE=1"

:report
echo.
if "%CODE%"=="0" echo   RESULT: all checks passed.
if "%CODE%"=="1" echo   RESULT: something did not pass - look for [FAIL] above.
if not "%CODE%"=="0" if not "%CODE%"=="1" echo   RESULT: the script itself crashed ^(code %CODE%^) - try again.
echo.

pause
