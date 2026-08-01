@echo off
REM ===========================================================================
REM  run-tests.bat  -  launcher for Harden-Windows11-v2_2.ps1
REM
REM  There is only ONE file that matters: Harden-Windows11-v2_2.ps1. It is fully
REM  self-contained for hardening (menu, all modules). This bat just
REM  opens its menu. The test files (0wintest-logic.py, Harden-Windows11.Tests.ps1)
REM  ship alongside; keep them together. Delete this bat and you lose nothing.
REM ===========================================================================
setlocal
set "HERE=%~dp0"
set "PS1=%HERE%Harden-Windows11-v2_2.ps1"

if not exist "%PS1%" (
    echo ERROR: cannot find "%PS1%"
    echo Put run-tests.bat in the same folder as Harden-Windows11-v2_2.ps1.
    echo(
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Menu

endlocal
