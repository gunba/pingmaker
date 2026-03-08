@echo off
REM ──────────────────────────────────────────────────────────
REM  Pingmaker — Core-only Nuitka build
REM  Produces: Pingmaker.exe (no weave engine / vision / Pico)
REM ──────────────────────────────────────────────────────────

REM Locate vendored pydivert's WinDivert DLL directory (local pydivert/ from xshiraori/PyDivert2 fork)
for /f "delims=" %%i in ('python -c "import pydivert, os; print(os.path.join(os.path.dirname(pydivert.__file__), 'windivert_dll'))"') do set PYDIVERT_DLL_DIR=%%i

python -m nuitka ^
    --assume-yes-for-downloads ^
    --enable-plugin=tk-inter ^
    --standalone ^
    --onefile ^
    --windows-console-mode=disable ^
    --windows-icon-from-ico=pingmaker.ico ^
    --include-data-files=pingmaker.ico=pingmaker.ico ^
    --include-data-files=pingmaker.png=pingmaker.png ^
    --include-data-files=skills.json=skills.json ^
    --include-package-data=pydivert ^
    --include-data-files=%PYDIVERT_DLL_DIR%\WinDivert.dll=pydivert/windivert_dll/WinDivert.dll ^
    --include-data-files=%PYDIVERT_DLL_DIR%\WinDivert64.sys=pydivert/windivert_dll/WinDivert64.sys ^
    --include-module=plugins.base ^
    --include-module=packet_model ^
    --nofollow-import-to=weave_engine ^
    --nofollow-import-to=plugins.weave_plugin ^
    --nofollow-import-to=plugins.conditional_logger ^
    --nofollow-import-to=cv2 ^
    --nofollow-import-to=numpy ^
    --nofollow-import-to=win32gui ^
    --nofollow-import-to=win32ui ^
    --nofollow-import-to=win32con ^
    --nofollow-import-to=raw_input_reader ^
    --nofollow-import-to=pico_bridge ^
    --output-filename=Pingmaker.exe ^
    pingmaker.py

echo.
if %ERRORLEVEL% EQU 0 (
    echo Build succeeded: Pingmaker.exe
) else (
    echo Build FAILED with error code %ERRORLEVEL%
)
pause
