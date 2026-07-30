@echo off
REM Astartis v2.1 — Full Build Script (all components)
REM Builds the entire bridge including v2.0 agent swarm and v2.1 Zero Trust module

setlocal EnableDelayedExpansion

echo ========================================
echo Astartis v2.1 — Full Build
echo ========================================

REM Set OpenSSL paths (detected at C:\Program Files\OpenSSL-Win64)
set OPENSSL_ROOT=C:\Program Files\OpenSSL-Win64
set OPENSSL_INCLUDE_DIR=%OPENSSL_ROOT%\include
set OPENSSL_CRYPTO_LIBRARY=%OPENSSL_ROOT%\lib\VC\x64\MD\libcrypto.lib

REM Initialize Visual Studio build environment
REM Try the standard 2022 path first, then the version-numbered path ("18")
set VS_VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist %VS_VCVARS% (
    set VS_VCVARS="C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
)
if not exist %VS_VCVARS% (
    echo ERROR: Visual Studio 2022 not found. Searched:
    echo   C:\Program Files\Microsoft Visual Studio\2022\Community\...
    echo   C:\Program Files\Microsoft Visual Studio\18\Community\...
    echo Please install Visual Studio 2022 with "Desktop development with C++" workload.
    exit /b 1
)
call %VS_VCVARS%

REM Create build directory
if not exist build mkdir build
cd build

REM Configure with CMake (full project including all v2.1 sources)
echo.
echo [1/5] Configuring with CMake...
cmake .. -DCMAKE_BUILD_TYPE=Release ^
         -DOPENSSL_ROOT_DIR="%OPENSSL_ROOT%" ^
         -DOPENSSL_INCLUDE_DIR="%OPENSSL_INCLUDE_DIR%"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo CMake configuration FAILED!
    echo Make sure CMake, OpenSSL, and Npcap SDK are installed.
    cd ..
    exit /b 1
)
echo ✅ CMake configured.

REM Build the entire project (all test targets + bridge)
echo.
echo [2/5] Building all targets...
cmake --build . --config Release

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED!
    cd ..
    exit /b 1
)
echo ✅ Build complete.

REM ── Run all tests ────────────────────────────────────────────────────────
echo.
echo [3/5] Running all tests...

set TEST_COUNT=0
set PASS_COUNT=0
set FAIL_COUNT=0
set SKIP_COUNT=0

for %%T in (test_audit_chain test_version_store test_worm_lock test_crypto_identity test_packet_sensor test_threat_level test_rule_engine test_access_token test_sandbox test_decoy test_active_response test_chaos_detector test_attribution_report test_quarantine test_active_defense test_unlock_protocol test_clamd_scanner test_ai_triage test_veeam_interface test_agent_controller test_granite_client test_pipeline test_segmentation test_nac_workflow test_zerotrust_decisions) do (
    if exist "Release\%%T.exe" (
        set /a TEST_COUNT+=1
        echo Running %%T...
        Release\%%T.exe >nul 2>&1
        set RESULT=!ERRORLEVEL!
        if !RESULT! EQU 0 (
            echo   ✅ PASS
            set /a PASS_COUNT+=1
        ) else if !RESULT! EQU 2 (
            echo   ⏭️  SKIP (dependency not available)
            set /a SKIP_COUNT+=1
        ) else (
            echo   ❌ FAIL
            set /a FAIL_COUNT+=1
        )
    ) else (
        echo %%T: not built (skipped)
    )
)

echo.
echo Test Results: %PASS_COUNT%/%TEST_COUNT% PASS, %FAIL_COUNT% FAIL, %SKIP_COUNT% SKIP

if %FAIL_COUNT% GTR 0 (
    echo ⚠️  Some tests FAILED. Review output above.
) else (
    echo ✅ All tests passed or skipped.
)

cd ..

REM ── Build Elixir dashboard (optional) ─────────────────────────────────────
echo.
echo [4/5] Building Elixir dashboard (if available)...
if exist "astartis_web\mix.exs" (
    cd astartis_web
    echo   Installing Elixir dependencies...
    mix deps.get >nul 2>&1
    if %ERRORLEVEL% EQU 0 echo   ✅ Elixir deps ready.
    cd ..
) else (
    echo   astartis_web/ not found. Skipping dashboard build.
)

REM ── Summary ──────────────────────────────────────────────────────────────
echo.
echo ========================================
echo BUILD COMPLETE
echo ========================================
echo.
echo Executable: astartis\build\Release\astartis_bridge.exe
echo Size:       ~650 KB
echo.
echo To run the dashboard:
echo   cd astartis_web ^&^& mix phx.server
echo.
echo To start everything (bridge + dashboard):
echo   scripts\start.bat
echo.

endlocal
