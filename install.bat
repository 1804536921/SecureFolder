@echo off
cd /d "%~dp0"
echo ====================================
echo SecureFolder Installation Script
echo ====================================
echo.

:: Check admin privileges
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Administrator privileges required!
    echo Please right-click and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

:: Set paths
set "INSTALL_DIR=%ProgramFiles%\SecureFolder"
set "DLL_PATH=%INSTALL_DIR%\SecureFolderShellExt.dll"
set "EXE_PATH=%INSTALL_DIR%\SecureFolder.exe"

echo [1/5] Creating installation directory...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

echo [2/5] Copying files...
copy /Y "build\Release\SecureFolder.exe" "%EXE_PATH%"
copy /Y "build\Release\SecureFolderShellExt.dll" "%DLL_PATH%"

if %ERRORLEVEL% neq 0 (
    echo Copy failed! Please run build.bat first.
    pause
    exit /b 1
)

echo [3/5] Registering Shell extension DLL...
regsvr32 /s "%DLL_PATH%"

if %ERRORLEVEL% neq 0 (
    echo DLL registration failed!
    pause
    exit /b 1
)

echo [4/5] Creating desktop shortcut...
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\\SecureFolder.lnk'); $s.TargetPath = '%EXE_PATH%'; $s.Save()"

echo [5/5] Registering .securefolder handler and context menu...

:: Register .securefolder extension - double-click will trigger our program
reg add "HKCR\.securefolder" /ve /d "SecureFolder.LockedFolder" /f

:: Register the locked folder type with icon
reg add "HKCR\SecureFolder.LockedFolder" /ve /d "SecureFolder Locked Folder" /f
reg add "HKCR\SecureFolder.LockedFolder\DefaultIcon" /ve /d "\"%EXE_PATH%\",0" /f

:: Set double-click action (open = unlock)
reg add "HKCR\SecureFolder.LockedFolder\shell" /ve /d "open" /f
reg add "HKCR\SecureFolder.LockedFolder\shell\open" /ve /d "Unlock" /f
reg add "HKCR\SecureFolder.LockedFolder\shell\open\command" /ve /d "\"%EXE_PATH%\" unlock-gui \"%%1\"" /f

:: Add unlock context menu
reg add "HKCR\SecureFolder.LockedFolder\shell\unlock" /ve /d "Unlock with SecureFolder" /f
reg add "HKCR\SecureFolder.LockedFolder\shell\unlock\command" /ve /d "\"%EXE_PATH%\" unlock-gui \"%%1\"" /f

:: Add context menu for normal folders (lock option)
reg add "HKCR\Folder\shell\SecureFolderEncrypt" /ve /d "Lock with SecureFolder" /f
reg add "HKCR\Folder\shell\SecureFolderEncrypt\command" /ve /d "\"%EXE_PATH%\" lock-gui \"%%1\"" /f

echo.
echo ====================================
echo Installation completed!
echo ====================================
echo.
echo Installation location: %INSTALL_DIR%
echo.
echo Features:
echo   - Double-click encrypted folder: Password dialog
echo   - Right-click any folder: Lock/Unlock options
echo   - Desktop shortcut: Main program GUI
echo.
echo Usage:
echo   1. Right-click folder - Select "Lock with SecureFolder"
echo   2. Enter password to encrypt
echo   3. Double-click encrypted folder - Enter password to unlock
echo.
echo Note: Explorer restart required for changes to take effect.
echo.

set /p RESTART="Restart Explorer now? (Y/N): "
if /I "%RESTART%"=="Y" (
    echo Restarting Explorer...
    taskkill /f /im explorer.exe > nul
    start explorer.exe
    echo Done!
)

echo.
pause