; AutoKRP installer (Inno Setup 6.3+ / 7). Built by build.bat:
;   ISCC.exe /DAppVer=1.56.0 /DSrcDir=<dist\installer\AutoKRP> [/DExeName=AutoKRP-Monitor /DAppGuid=<guid>] /O<dist> installer\AutoKRP.iss
; The installer copies the program only. Data stays where it is (%LOCALAPPDATA%\AutoKRP or the folder chosen
; at first start), so an installed copy continues with the data of the portable exe for the same Windows user.
; Uninstalling never deletes data.

#ifndef AppVer
  #define AppVer "0.0.0"
#endif
#ifndef SrcDir
  #define SrcDir "..\dist\installer\AutoKRP"
#endif
; 1.56 modular builds: build.bat passes the exe name (AutoKRP-Monitor, ...) and its own AppId, so a custom build
; installs next to the full app instead of replacing it. Data is shared (same data folder).
#ifndef ExeName
  #define ExeName "AutoKRP"
#endif
#ifndef AppGuid
  #define AppGuid "AD6B0823-5846-4C49-9730-7DAAD1702EE9"
#endif

[Setup]
AppId={{{#AppGuid}}
AppName={#ExeName}
AppVersion={#AppVer}
AppVerName={#ExeName} {#AppVer}
AppPublisher=Kamyar RP
AppPublisherURL=https://github.com/kamyar-rp/AutoKRP
AppSupportURL=https://github.com/kamyar-rp/AutoKRP/issues
VersionInfoVersion={#AppVer}
DefaultDirName={autopf}\{#ExeName}
DefaultGroupName={#ExeName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputBaseFilename={#ExeName}-Setup-{#AppVer}
; 1.59.4: build.bat passes a clean icon made by dev\mkicon.py (default Inno icon when there is none)
#ifdef SetupIcon
SetupIconFile={#SetupIcon}
#endif
UninstallDisplayIcon={app}\{#ExeName}.exe
UninstallDisplayName={#ExeName} {#AppVer}
LicenseFile=..\LICENSE
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
; 1.59.3: inbound Windows Firewall rule for server (web) mode; tied to the program file, so changing the port later still works
Name: "firewall"; Description: "Allow the web server through Windows Firewall (server mode)"; GroupDescription: "Windows Firewall:"

[Files]
Source: "{#SrcDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; files of the previous version that are no longer shipped (the program folder is replaced as a whole)
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{autoprograms}\{#ExeName}"; Filename: "{app}\{#ExeName}.exe"
Name: "{autodesktop}\{#ExeName}"; Filename: "{app}\{#ExeName}.exe"; Tasks: desktopicon

[Run]
; close a running copy (for example the portable exe in the tray) of the user who started the setup
Filename: "{app}\{#ExeName}.exe"; Parameters: "--quit-running"; Flags: runhidden waituntilterminated runasoriginaluser; StatusMsg: "Closing a running AutoKRP..."
; Windows Firewall rule (as Administrator); allowed networks and Trap/Syslog ports are applied later from the server window
Filename: "{app}\{#ExeName}.exe"; Parameters: "--firewall-apply --quiet"; Flags: runhidden waituntilterminated; Tasks: firewall; StatusMsg: "Windows Firewall rule..."
; start as the user who started the setup (not as Administrator): the data folder belongs to that user
Filename: "{app}\{#ExeName}.exe"; Description: "{cm:LaunchProgram,{#ExeName}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
; 1.59.3: remove this edition's Windows Firewall rules (data is never deleted)
Filename: "{app}\{#ExeName}.exe"; Parameters: "--firewall-remove --quiet"; Flags: runhidden waituntilterminated; RunOnceId: "AutoKRPFirewall"

[UninstallDelete]
Type: dirifempty; Name: "{app}"

[Messages]
FinishedLabel=AutoKRP is installed.%n%nYour data was not moved or changed: open AutoKRP with the same Windows user to continue with it. If server auto-start was set up from the portable exe, open the app and choose "Update to this copy".

[Code]
// Before files are replaced: close the running installed copy (its files are in use).
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  rc: Integer;
  exe: String;
begin
  Result := '';
  exe := ExpandConstant('{app}\{#ExeName}.exe');
  if FileExists(exe) then
    ExecAsOriginalUser(exe, '--quit-running', '', SW_HIDE, ewWaitUntilTerminated, rc);
end;

// Uninstall: close a running copy first; data is never deleted.
function InitializeUninstall(): Boolean;
var
  rc: Integer;
  exe: String;
begin
  exe := ExpandConstant('{app}\{#ExeName}.exe');
  if FileExists(exe) then
    Exec(exe, '--quit-running', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and not UninstallSilent then
    MsgBox('AutoKRP was removed. Your data was kept (%LOCALAPPDATA%\AutoKRP or the folder you chose). ' +
           'To delete it, use RESET in the app before uninstalling, or delete that folder yourself. ' +
           'If server auto-start was enabled, remove it from the app first or delete the "AutoKRP Server" task in Task Scheduler.',
           mbInformation, MB_OK);
end;
