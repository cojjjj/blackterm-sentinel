@echo off
setlocal

where go >nul 2>nul
if errorlevel 1 (
  echo [!] Go is not installed or not in PATH.
  exit /b 1
)

if not exist sentinel.exe (
  echo [*] Building BLACKTERM // SENTINEL...
  go build -o sentinel.exe ./cmd/sentinel
  if errorlevel 1 exit /b 1
)

sentinel.exe %*
