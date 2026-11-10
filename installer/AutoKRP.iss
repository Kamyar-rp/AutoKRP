; AutoKRP installer (Inno Setup 6.3+ / 7). Built by build.bat:
;   ISCC.exe /DAppVer=1.52.0 /DSrcDir=<dist\installer\AutoKRP> /O<dist> installer\AutoKRP.iss
; The installer copies the program only. Data stays where it is (%LOCALAPPDATA%\AutoKRP or the folder chosen
; at first start), so an installed copy continues with the data of the portable exe for the same Windows user.
; Uninstalling never deletes data.

#ifndef AppVer
  #define AppVer "0.0.0"
#endif
#ifndef SrcDir
  #define SrcDir "..\dist\installer\AutoKRP"
#endif

[Setup]
AppId={{AD6B0823-5846-4C49-9730-7DAAD1702EE9}
AppName=AutoKRP
AppVersion={#AppVer}
AppVerName=AutoKRP {#AppVer}
AppPublisher=Kamyar RP
AppPublisherURL=https://github.com/kamyar-rp/AutoKRP
AppSupportURL=https://github.com/kamyar-rp/AutoKRP/issues
VersionInfoVersion={#AppVer}
DefaultDirName={autopf}\AutoKRP
DefaultGroupName=AutoKRP
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputBaseFilename=AutoKRP-Setup-{#AppVer}
SetupIconFile=..\assets\app.ico
UninstallDisplayIcon={app}\AutoKRP.exe
UninstallDisplayName=AutoKRP {#AppVer}
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

[Files]
Source: "{#SrcDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; files of the previous version that are no longer shipped (the program folder is replaced as a whole)
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{autoprograms}\AutoKRP"; Filename: "{app}\AutoKRP.exe"
Name: "{autodesktop}\AutoKRP"; Filename: "{app}\AutoKRP.exe"; Tasks: desktopicon

[Run]
; close a running copy (for example the portable exe in the tray) of the user who started the setup
Filename: "{app}\AutoKRP.exe"; Parameters: "--quit-running"; Flags: runhidden waituntilterminated runasoriginaluser; StatusMsg: "Closing a running AutoKRP..."
; start as the user who started the setup (not as Administrator): the data folder belongs to that user
Filename: "{app}\AutoKRP.exe"; Description: "{cm:LaunchProgram,AutoKRP}"; Flags: nowait postinstall skipifsilent runasoriginaluser

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
  exe := ExpandConstant('{app}\AutoKRP.exe');
  if FileExists(exe) then
    ExecAsOriginalUser(exe, '--quit-running', '', SW_HIDE, ewWaitUntilTerminated, rc);
end;

// Uninstall: close a running copy first; data is never deleted.
function InitializeUninstall(): Boolean;
var
  rc: Integer;
  exe: String;
begin
  exe := ExpandConstant('{app}\AutoKRP.exe');
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
