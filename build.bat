@echo off
setlocal EnableExtensions
cd /d "%~dp0"
rem Official build: isolated venv (.venv-build), stop on any error, dependency audit,
rem record exact versions and SHA-256 next to the outputs in dist\.
rem   build.bat            asks what to build (menu), then: portable exe + installer
rem   build.bat portable   full build, portable exe only (used by the release script; only the portable exe is published)
rem 1.56 modular builds - choose the sections and the mode that go into the exe (details: dev\mkbuild.py, autokrp\buildcfg.py):
rem   build.bat full                     everything (dist\AutoKRP.exe + dist\AutoKRP-Setup-X.Y.Z.exe), no questions
rem   build.bat monitor                  monitoring only  (dist\AutoKRP-Monitor.exe)
rem   build.bat monitor server           monitoring only, server (web) mode only  (dist\AutoKRP-Monitor-Server.exe)
rem   build.bat sec+dev client portable  several sections (sec, dev, monitor, asset, offline), client only, no installer
rem   modes: both (default, asked at first start) ^| client ^| server
rem A section that is left out is really not in the exe: no engine code, no pages, no API methods, no libraries.
rem Build tools (1.52): put the files listed in vendor\README.md into vendor\. Nothing is installed system-wide:
rem Python goes to .pybuild\ and Inno Setup to .innosetup\ (current user only) when they are not already present.
call :pick_python || goto :err
rem 1.56: decide first (menu when no section was given and a console is attached), then prepare the tools
if not exist build mkdir build
if exist build\build_choice.cmd del build\build_choice.cmd
"%BASEPY%" dev\mkbuild.py --ask %*
if errorlevel 1 goto :err
if not exist build\build_choice.cmd goto :err
call build\build_choice.cmd
set "VENVVER="
if exist ".venv-build\Scripts\python.exe" (
  for /f "delims=" %%V in ('call ".venv-build\Scripts\python.exe" -c "import sys;print(sys.version_info[0],sys.version_info[1],sep='.')"') do set "VENVVER=%%V"
)
if exist ".venv-build\Scripts\python.exe" if not "%VENVVER%"=="%BASEMM%" (
  echo .venv-build uses Python %VENVVER%; recreating it with %BASEMM% ...
  rmdir /s /q ".venv-build" || goto :err
)
if not exist ".venv-build\Scripts\python.exe" (
  "%BASEPY%" -m venv .venv-build || goto :err
)
set PY=.venv-build\Scripts\python.exe
"%PY%" -m pip install --upgrade pip || goto :err
if exist requirements-lock.txt (
  echo Using requirements-lock.txt
  "%PY%" -m pip install -r requirements-lock.txt || goto :err
  rem 1.57: the minimum (security) versions of requirements.txt still apply on top of an older lock file
  "%PY%" -m pip install -r requirements.txt || goto :err
) else (
  "%PY%" -m pip install -r requirements.txt || goto :err
)
rem 1.33: exact list of bundled libraries for "About -> security check" (vulnerability check against OSV)
"%PY%" dev\deps_snapshot.py || goto :err
"%PY%" -m pip install pip-audit >nul
echo.
echo === Dependency audit (pip-audit) ===
rem GHSA-r374-rxx8-8654 (paramiko SHA-1): no fixed release yet; SHA-1 is disabled except per-device legacy switch
rem Network failure (timeout to pypi.org) is not the same as a vulnerability: retry with OSV, then report clearly.
set AUDLOG=%TEMP%\autokrp_audit.txt
"%PY%" -m pip_audit -l --timeout 60 --progress-spinner off --ignore-vuln GHSA-r374-rxx8-8654 > "%AUDLOG%" 2>&1
if not errorlevel 1 goto :audit_ok
call :audit_neterr && goto :audit_osv
type "%AUDLOG%"
echo.
echo [WARNING] pip-audit reported vulnerable packages. Review before publishing.
echo.
goto :audit_done
:audit_osv
echo pypi.org did not answer in time; retrying the audit with osv.dev ...
"%PY%" -m pip_audit -l -s osv --timeout 60 --progress-spinner off --ignore-vuln GHSA-r374-rxx8-8654 > "%AUDLOG%" 2>&1
if not errorlevel 1 goto :audit_ok
call :audit_neterr && goto :audit_offline
type "%AUDLOG%"
echo.
echo [WARNING] pip-audit reported vulnerable packages. Review before publishing.
echo.
goto :audit_done
:audit_offline
echo.
echo [WARNING] Dependency audit SKIPPED: no connection to pypi.org / osv.dev (network timeout).
echo           This is not a vulnerability. The build continues; run dev\security_check.bat later when online.
echo.
goto :audit_done
:audit_ok
type "%AUDLOG%"
echo Dependency audit: OK
:audit_done
del "%AUDLOG%" >nul 2>&1
rem ---- 1.56: staged source for the chosen profile + PyInstaller (one-file exe, and the folder build for the installer) ----
if exist build\last_build.cmd del build\last_build.cmd
"%PY%" dev\mkbuild.py %BUILDARGS% || goto :err
if not exist build\last_build.cmd goto :err
call build\last_build.cmd
if not exist "dist\%EXENAME%.exe" goto :err
"%PY%" -m pip freeze > "dist\%EXENAME%-build-requirements.txt"
"%PY%" --version > "dist\%EXENAME%-build-python.txt"
certutil -hashfile "dist\%EXENAME%.exe" SHA256 > "dist\%EXENAME%.exe.sha256.txt"
set "SETUPNOTE=(skipped: portable)"
if "%INSTDIR%"=="" goto :done
rem ---- 1.52: installer (PyInstaller folder build + Inno Setup) ----
set "SETUPNOTE="
for /f "delims=" %%V in ('call "%PY%" -c "import autokrp;print(autokrp.__version__)"') do set "VER=%%V"
if not exist "%INSTDIR%\%EXENAME%.exe" goto :err
call :pick_iscc
if not defined ISCC (
  set "SETUPNOTE=(NOT built: Inno Setup not found - see vendor\README.md)"
  goto :done
)
if exist "dist\%EXENAME%-Setup-%VER%.exe" del "dist\%EXENAME%-Setup-%VER%.exe"
rem 1.59.4: Inno Setup accepts only a clean .ico; convert assets\app.ico (or app.png) to build\setup.ico first
set "SETUPICON="
for /f "delims=" %%I in ('call "%PY%" dev\mkicon.py "%CD%\build\setup.ico"') do set "SETUPICON=%%I"
rem (no parenthesised block here: a ")" in the folder path would break it)
set "ICONARG=/DNoSetupIcon=1"
if defined SETUPICON set "ICONARG=/DSetupIcon=%SETUPICON%"
"%ISCC%" /Q "/DAppVer=%VER%" "/DSrcDir=%INSTDIR%" "/DExeName=%EXENAME%" "/DAppGuid=%APPGUID%" "%ICONARG%" "/O%CD%\dist" installer\AutoKRP.iss
if errorlevel 1 (
  set "SETUPNOTE=(FAILED: Inno Setup reported an error above)"
  goto :done
)
certutil -hashfile "dist\%EXENAME%-Setup-%VER%.exe" SHA256 > "dist\%EXENAME%-Setup-%VER%.exe.sha256.txt"
set "SETUPNOTE=dist\%EXENAME%-Setup-%VER%.exe (+ .sha256.txt)"
:done
echo.
echo Build:  %EXENAME%   sections: %BUILDMODS%   mode: %BUILDMODE%
echo Output: dist\%EXENAME%.exe  (portable)
echo         dist\%EXENAME%.exe.sha256.txt
echo         dist\%EXENAME%-build-requirements.txt  (exact versions; copy to requirements-lock.txt to pin future builds)
echo Installer: %SETUPNOTE%
pause
exit /b 0

:pick_python
rem Build Python: .pybuild\ ^> Python 3.14 from the py launcher ^> vendor\python-3.14*-amd64.exe (installed into .pybuild\) ^> python on PATH
set "BASEPY="
if exist ".pybuild\python.exe" set "BASEPY=%CD%\.pybuild\python.exe"
if defined BASEPY goto :py_ok
where py >nul 2>&1
if not errorlevel 1 (
  for /f "delims=" %%P in ('py -3.14 -c "import sys;print(sys.executable)" 2^>nul') do set "BASEPY=%%P"
)
if defined BASEPY goto :py_ok
set "PYINST="
for %%F in (vendor\python-3.14*-amd64.exe) do set "PYINST=%%F"
if defined PYINST (
  echo Installing build Python from %PYINST% into .pybuild\ ^(current user, no PATH change^) ...
  start "" /wait "%PYINST%" /quiet InstallAllUsers=0 "TargetDir=%CD%\.pybuild" Include_launcher=0 InstallLauncherAllUsers=0 Include_test=0 Include_doc=0 Include_tcltk=0 Include_pip=1 PrependPath=0 Shortcuts=0 AssociateFiles=0 CompileAll=0
  if exist ".pybuild\python.exe" set "BASEPY=%CD%\.pybuild\python.exe"
  if not exist ".pybuild\python.exe" echo [WARNING] The Python setup did not install into .pybuild\ ^(already installed for this user?^). Trying python on PATH.
)
if defined BASEPY goto :py_ok
for /f "delims=" %%P in ('python -c "import sys;print(sys.executable)" 2^>nul') do set "BASEPY=%%P"
if defined BASEPY goto :py_ok
echo [ERROR] No Python found. Put python-3.14.x-amd64.exe into vendor\ ^(see vendor\README.md^) or install Python 3.14.
exit /b 1
:py_ok
for /f "delims=" %%V in ('call "%BASEPY%" -c "import sys;print(sys.version_info[0],sys.version_info[1],sep='.')"') do set "BASEMM=%%V"
echo Build Python: %BASEPY% ^(%BASEMM%^)
exit /b 0

:pick_iscc
rem Inno Setup compiler: .innosetup\ ^> installed Inno Setup 7/6 ^> vendor\innosetup-*.exe (installed into .innosetup\, current user)
set "ISCC="
for %%D in ("%CD%\.innosetup" "%LOCALAPPDATA%\Programs\Inno Setup 7" "%ProgramFiles%\Inno Setup 7" "%ProgramFiles(x86)%\Inno Setup 7" "%LOCALAPPDATA%\Programs\Inno Setup 6" "%ProgramFiles%\Inno Setup 6" "%ProgramFiles(x86)%\Inno Setup 6") do (
  if not defined ISCC if exist "%%~D\ISCC.exe" set "ISCC=%%~D\ISCC.exe"
)
if defined ISCC exit /b 0
set "INNOINST="
for %%F in (vendor\innosetup-*.exe) do set "INNOINST=%%F"
if not defined INNOINST exit /b 1
echo Installing Inno Setup from %INNOINST% into .innosetup\ ^(current user^) ...
start "" /wait "%INNOINST%" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /CURRENTUSER /NOICONS "/DIR=%CD%\.innosetup"
if exist ".innosetup\ISCC.exe" set "ISCC=%CD%\.innosetup\ISCC.exe"
if defined ISCC exit /b 0
exit /b 1

:audit_neterr
rem errorlevel 0 = the audit failed because of the network, not because of a finding
findstr /i /c:"timed out" /c:"ConnectionError" /c:"Max retries" /c:"NameResolutionError" /c:"getaddrinfo failed" /c:"SSLError" "%AUDLOG%" >nul
exit /b %errorlevel%

:err
echo.
echo BUILD FAILED - see the messages above.
pause
exit /b 1
