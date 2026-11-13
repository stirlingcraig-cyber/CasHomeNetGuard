@echo off
REM Builds a single self-contained CasHomeNetGuard.exe (no .NET install needed on target PCs)
REM Requires the .NET 8 SDK: https://dotnet.microsoft.com/download/dotnet/8.0
cd /d "%~dp0"
dotnet publish CasHomeNetGuard.csproj -c Release -o publish
if errorlevel 1 (echo Build failed & pause & exit /b 1)
echo.
echo Done:  %~dp0publish\CasHomeNetGuard.exe
pause
