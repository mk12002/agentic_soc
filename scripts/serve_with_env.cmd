@echo off
rem Start the platform from Command Prompt with .env loaded (the platform reads settings only from the environment,
rem and scripts\load_env.ps1 is a PowerShell loader). Values are never printed.
rem   scripts\serve_with_env.cmd          start the server
rem   scripts\serve_with_env.cmd reset    reset the demo data first (server must be stopped), then start
cd /d "%~dp0.."
if not exist ".venv\Scripts\python.exe" (echo No .venv here - create it first, see docs\RUN_GUIDE.md & exit /b 1)
if not exist ".env" (echo No .env here - copy .env.example to .env and fill it in & exit /b 1)
set "STEP=.\.venv\Scripts\python -m soc_platform serve"
if /i "%~1"=="reset" set "STEP=.\.venv\Scripts\python -m soc_platform reset-demo --yes; if ($LASTEXITCODE -eq 0) { .\.venv\Scripts\python -m soc_platform serve }"
powershell -NoProfile -ExecutionPolicy Bypass -Command ". .\scripts\load_env.ps1; %STEP%"
