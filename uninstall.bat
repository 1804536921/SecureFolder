@echo off
cd /d "%~dp0"
echo ====================================
echo SecureFolder Uninstallation Script
echo ====================================
echo.

:: Check admin privileges
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Administrator privileges required!
    echo Please right-click and select "Run as administrator"
    pause
    exit /b 1
)

set "INSTALL_DIR=%ProgramFiles%\SecureFolder"
set "DLL_PATH=%INSTALL_DIR%\SecureFolderShellExt.dll"

echo [1/4] Unregistering Shell extension DLL...
regsvr32 /s /u "%DLL_PATH%"

echo [2/4] Removing context menu items and .securefolder handler...
reg delete "HKEY_CLASSES_ROOT\.securefolder" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\SecureFolder.LockedFolder" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\Folder\shell\SecureFolderEncrypt" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\Folder\shell\SecureFolderDecrypt" /f > nul 2>&1

echo [3/4] Removing desktop shortcut...
del /f /q "%USERPROFILE%\Desktop\SecureFolder.lnk" > nul 2>&1

echo [4/4] Removing installation directory...
rd /s /q "%INSTALL_DIR%" > nul 2>&1

echo.
echo ====================================
echo Uninstallation completed!
echo ====================================
echo.
echo Recommend restarting Explorer to clear cache.
echo.

set /p RESTART="Restart Explorer now? (Y/N): "
if /I "%RESTART%"=="Y" (
    taskkill /f /im explorer.exe > nul
    start explorer.exe
    echo Done!
)

pause