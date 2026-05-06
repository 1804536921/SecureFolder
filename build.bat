@echo off
echo ====================================
echo SecureFolder Build Script
echo ====================================
echo.

if not exist build mkdir build

cd build

set CMAKE_PATH="C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

echo [1/3] Configuring project...
%CMAKE_PATH% .. -G "Visual Studio 17 2022" -A x64

if %ERRORLEVEL% neq 0 (
    echo.
    echo Configuration failed!
    echo Please make sure CMake and Visual Studio 2022 are installed.
    echo.
    pause
    exit /b 1
)

echo.
echo [2/3] Building project (Release)...
%CMAKE_PATH% --build . --config Release

if %ERRORLEVEL% neq 0 (
    echo.
    echo Build failed!
    echo.
    pause
    exit /b 1
)

echo.
echo [3/3] Build completed!
echo.
echo Output: build\Release\SecureFolder.exe
echo.

cd ..

echo Usage:
echo   SecureFolder.exe lock "folder_path"    - Lock folder
echo   SecureFolder.exe unlock "folder_path"  - Unlock folder
echo   SecureFolder.exe gui                   - Open GUI
echo   SecureFolder.exe help                  - Show help
echo.

pause