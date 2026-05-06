@echo off
echo ====================================
echo SecureFolder Clean Build Script
echo ====================================
echo.

echo Cleaning build cache...

:: Delete build directory
if exist build (
    rd /s /q build
    echo Build directory deleted.
) else (
    echo No build directory found.
)

echo.
echo Clean completed!
echo Now run build.bat to compile.
echo.
pause