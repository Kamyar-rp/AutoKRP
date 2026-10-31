@echo off
setlocal
cd /d "%~dp0"
rem Official build: isolated venv (.venv-build), stop on any error, dependency audit,
rem record exact versions and SHA-256 of the exe next to it in dist\.
if not exist ".venv-build\Scripts\python.exe" (
  python -m venv .venv-build || goto :err
)
set PY=.venv-build\Scripts\python.exe
"%PY%" -m pip install --upgrade pip || goto :err
if exist requirements-lock.txt (
  echo Using requirements-lock.txt
  "%PY%" -m pip install -r requirements-lock.txt || goto :err
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
set ICON=assets\app.ico
if exist "%ICON%" (set ICONARG=--icon "%ICON%") else (set ICONARG=)
"%PY%" -m PyInstaller --noconfirm --clean --onefile --windowed --name AutoKRP %ICONARG% --add-data "ui;ui" --add-data "assets\app.png;assets" --add-data "assets\mibs;assets\mibs" --add-data "autokrp\trapdb.json;autokrp" --add-data "autokrp\oui.dat;autokrp" --add-data "autokrp\build_deps.txt;autokrp" --collect-submodules serial --hidden-import pystray._win32 --hidden-import pymysql --hidden-import autokrp.fgtask_child --hidden-import autokrp.snmpworker --hidden-import autokrp.snmppool --hidden-import autokrp.tsdb --hidden-import autokrp.icmp --collect-submodules netmiko --collect-submodules dns --collect-submodules pysnmp --collect-submodules ldap3 --collect-all pysmi --collect-data lark --hidden-import sqlcipher3 --collect-binaries sqlcipher3 app.py || goto :err
if not exist dist\AutoKRP.exe goto :err
"%PY%" -m pip freeze > dist\AutoKRP-build-requirements.txt
"%PY%" --version > dist\AutoKRP-build-python.txt
certutil -hashfile dist\AutoKRP.exe SHA256 > dist\AutoKRP.exe.sha256.txt
echo.
echo Output: dist\AutoKRP.exe
echo         dist\AutoKRP.exe.sha256.txt  (publish with the release)
echo         dist\AutoKRP-build-requirements.txt  (exact versions; copy to requirements-lock.txt to pin future builds)
pause
exit /b 0

:audit_neterr
rem errorlevel 0 = the audit failed because of the network, not because of a finding
findstr /i /c:"timed out" /c:"ConnectionError" /c:"Max retries" /c:"NameResolutionError" /c:"getaddrinfo failed" /c:"SSLError" "%AUDLOG%" >nul
exit /b %errorlevel%

:err
echo.
echo BUILD FAILED - see the messages above.
pause
exit /b 1
