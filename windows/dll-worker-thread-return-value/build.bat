@echo off

rem These options replicate Visual Studio
rem /MD: Use UCRT instead of statically linking CRT into modules
rem /INCREMENTAL:NO: Remove "ILT" from symbol names
cl lib.cpp /DUNICODE /D_UNICODE /MD /LD /EHsc /Zi /DEBUG /link /INCREMENTAL:NO
cl exe-test.c lib.lib /DUNICODE /D_UNICODE /MD /Zi /DEBUG /link /INCREMENTAL:NO

rem Helper: If compilation fails because cl command doesn't exist then re-run in the correct environment
if %ERRORLEVEL% equ 9009 (
    echo Compiler not found. Opening Visual Studio developer environment...
    set "VSCMD_START_DIR=%cd%"
    set "VSCMD_SKIP_SENDTELEMETRY=1"
    rem Find the latest x64 Developer CMD version then open it
    rem ^&: Inject running our build script after Visual Studio script (bug -> feature)
    for /f "delims=" %%f in ('dir /b /s /A-D /O-N "%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\x64 Native Tools Command Prompt for VS *.lnk"') do start "" "%%f" ^& build.bat & goto :EOF
)
