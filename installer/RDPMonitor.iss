; Native elevated wizard. Build only through scripts/build-installer.ps1.
#ifndef PackageDir
  #error PackageDir is required
#endif
#ifndef ReleaseVersion
  #error ReleaseVersion is required
#endif
#ifndef OutputDir
  #error OutputDir is required
#endif
#ifndef PublisherThumbprint
  #define PublisherThumbprint ""
#endif
#ifdef GuestOnly
  #define ProductPrefix "RDPMonitorGuest"
  #define ProductLabel "RDPMonitor Guest background agent"
#else
  #define ProductPrefix "RDPMonitor"
  #define ProductLabel "RDPMonitor"
#endif
#ifdef UnsignedPreview
  #define DisplayName ProductLabel + " UNSIGNED monitoring-only preview"
  #define ArtifactName ProductPrefix + "-" + ReleaseVersion + "-windows-x64-UNSIGNED-PREVIEW-setup"
#else
  #ifndef ProductionSigned
    #error Production setup requires the authenticated signed build pipeline; use explicit UnsignedPreview for monitoring-only evaluation
  #endif
  #define DisplayName ProductLabel
  #define ArtifactName ProductPrefix + "-" + ReleaseVersion + "-windows-x64-setup"
#endif

[Setup]
#ifdef GuestOnly
AppId={{25D349CB-74F1-4D78-984B-777A296B26B4}
#else
AppId={{568BEECA-79EC-48D2-BC98-36776044AE41}
#endif
AppName={#DisplayName}
AppVersion={#ReleaseVersion}
AppPublisher=RDPMonitor contributors
DefaultDirName={autopf}\RDPMonitor
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename={#ArtifactName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupLogging=no
CloseApplications=no
RestartApplications=no
UninstallDisplayName={#DisplayName}
#ifdef GuestOnly
UninstallFilesDir={app}\uninstall-guest
#else
UninstallFilesDir={app}\uninstall
#endif
#ifdef ProductionSigned
SignTool=publisher
SignedUninstaller=yes
#endif

[Files]
; A complete private bootstrap runtime, used before any secret is written. The
; signed setup authenticates this embedded copy; it is never an arbitrary Python.
Source: "{#PackageDir}\agent\*"; DestDir: "{tmp}\bootstrap"; Flags: dontcopy recursesubdirs createallsubdirs
#ifdef GuestOnly
Source: "{#PackageDir}\*"; DestDir: "{app}\releases\{#ReleaseVersion}"; Excludes: "client,client\*"; Flags: ignoreversion recursesubdirs createallsubdirs
#else
Source: "{#PackageDir}\*"; DestDir: "{app}\releases\{#ReleaseVersion}"; Flags: ignoreversion recursesubdirs createallsubdirs
#endif

#ifndef GuestOnly
[Icons]
Name: "{commonprograms}\RDPMonitor"; Filename: "{app}\releases\{#ReleaseVersion}\client\rdpmonitor.exe"
#endif

[Code]
var
  InvitationPage: TInputQueryWizardPage;
  ModePage: TInputOptionWizardPage;
  CodePage: TWizardPage;
  CodeMemo: TNewMemo;
  CodeLabel: TNewStaticText;
  CopyButton, RefreshButton: TNewButton;
  ReadOnlyCheck: TNewCheckBox;
  Session, SessionDir, Bootstrap, InstalledRelease: String;
  Registered, PairOnly, FinishedPairing, Prepared, PostInstallFailed, CmdBootstrap: Boolean;

function SetEnvironmentVariable(Name: String; Value: Integer): Boolean;
  external 'SetEnvironmentVariableW@kernel32.dll stdcall';

procedure ClearCommandEnvironment;
begin
  SetEnvironmentVariable('RDP_MONITOR_SETUP', 0);
  SetEnvironmentVariable('RDP_MONITOR_PREVIEW_ACCEPT', 0);
  SetEnvironmentVariable('RDP_MONITOR_INSTALLER_URL', 0);
  SetEnvironmentVariable('RDP_MONITOR_INSTALLER_SHA256', 0);
  SetEnvironmentVariable('RDP_MONITOR_INSTALLER_MODE', 0);
  SetEnvironmentVariable('RDP_MONITOR_PUBLISHER', 0);
  SetEnvironmentVariable('RDP_MONITOR_BOOTSTRAP', 0);
end;

function HasSwitch(const Name: String): Boolean;
var I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/' + Name) = 0 then Result := True;
end;

function Quote(const Value: String): String;
begin
  Result := '"' + Value + '"';
end;

function InvokeHelper(const Executable, Arguments: String): Boolean;
var ExitCode: Integer;
begin
  Result := Exec(Executable, 'setup ' + Arguments, '', SW_HIDE, ewWaitUntilTerminated, ExitCode);
  if Result then Result := ExitCode = 0;
end;

function ReadResult(const Name: String): String;
var Data: AnsiString;
begin
  if LoadStringFromFile(SessionDir + '\' + Name, Data) then Result := Trim(UTF8Decode(Data))
  else Result := '';
end;

procedure ShowCode;
begin
  CodeMemo.Text := ReadResult('connection.txt');
  if ReadResult('automatic.txt') = '1' then
    CodeLabel.Caption := ReadResult('status.txt') + #13#10 +
      'Keep Add machine open on the originating desktop (or reopen it to resume). The code below is optional manual recovery only; private, single-use, expires after five minutes.'
  else
    CodeLabel.Caption := ReadResult('status.txt') + #13#10 + 'Expires (Unix UTC seconds): ' + ReadResult('expires.txt') + #13#10 +
      'Paste into advanced Connect with code in the desktop app. Treat this URI like a password.';
  if ReadResult('automatic.txt') = '1' then RefreshButton.Caption := 'New manual code'
  else RefreshButton.Caption := 'Generate fresh code';
end;

procedure CopyCode(Sender: TObject);
begin
  CodeMemo.SelectAll;
  SendMessage(CodeMemo.Handle, $0301, 0, 0); // WM_COPY on the native read-only memo.
end;

procedure RefreshCode(Sender: TObject);
var Agent: String;
begin
  if ReadResult('automatic.txt') = '1' then
    if MsgBox('Generate a new advanced recovery code? This replaces the VM pairing approval, so automatic enrollment may stop. Use the new code with advanced Connect with code on your desktop.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) <> IDYES then exit;
  Agent := InstalledRelease + '\agent\RDPMonitorAgent.exe';
  if InvokeHelper(Agent, 'pair --session ' + Session) then ShowCode
  else MsgBox(ReadResult('status.txt'), mbError, MB_OK);
end;

function InitializeSetup: Boolean;
begin
  Result := False;
  CmdBootstrap := HasSwitch('CMDBOOTSTRAP');
  if CmdBootstrap then begin
#ifdef GuestOnly
    if not WizardSilent or not IsAdmin then begin
      ClearCommandEnvironment;
      exit;
    end;
#ifdef UnsignedPreview
    if not HasSwitch('ACCEPTUNSIGNEDMONITORINGONLY') or
      (GetEnv('RDP_MONITOR_PREVIEW_ACCEPT') <> 'I_ACCEPT_UNSIGNED_MONITORING_ONLY') then begin
      ClearCommandEnvironment;
      exit;
    end;
#endif
    Result := True;
    exit;
#else
    ClearCommandEnvironment;
    exit;
#endif
  end;
  ClearCommandEnvironment;
  if WizardSilent then exit;
#ifdef UnsignedPreview
  if MsgBox('UNSIGNED PREVIEW: this installer is not authenticated by a production publisher. It is for evaluation only and FORCES monitoring-only mode. It cannot enable administration, schedules or automatic RDP/firewall/account changes. Continue only if you independently trust this preview source?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) <> IDYES then exit;
#endif
  Result := True;
end;

procedure InitializeWizard;
var Arguments: String; Imported: Boolean;
begin
  Session := GetMD5OfString(GetDateTimeString('yyyymmddhhnnsszzz', '-', ':') + IntToStr(Random(2147483647)) + ExpandConstant('{tmp}'));
  SessionDir := ExpandConstant('{commonappdata}\RDPMonitor\setup\') + Session;
  ExtractTemporaryFiles('{tmp}\bootstrap\*');
  Bootstrap := ExpandConstant('{tmp}\bootstrap\RDPMonitorAgent.exe');
  if CmdBootstrap then begin
    Arguments := 'import-command --session ' + Session;
#ifdef UnsignedPreview
    Arguments := Arguments + ' --unsigned-preview --preview-consent';
#endif
    try
      Imported := InvokeHelper(Bootstrap, Arguments);
    finally
      ClearCommandEnvironment;
    end;
    if not Imported then
      RaiseException('Command setup rejected. Use an Administrator CMD, a fresh VM, a valid HTTPS setup command and explicit preview consent. No services were installed.');
  end else if not InvokeHelper(Bootstrap, 'prepare --session ' + Session) then
    RaiseException('Cannot prepare administrator/SYSTEM-owned setup exchange. No invitation was written.');
  Prepared := True;
  InstalledRelease := ReadResult('release.txt');
  Registered := ReadResult('registered.txt') = '1';
  ModePage := CreateInputOptionPage(wpWelcome, 'Agent maintenance', 'Preserve this machine identity and enrolled devices',
    'Generate a new private code without consuming another installation invitation, or repair this same packaged release. Version/trust changes use the signed update lifecycle.', True, False);
  ModePage.Add('Pair installed agent: generate a new five-minute connection code');
  ModePage.Add('Repair the same release: preserve identity, devices, relay and stored data');
  ModePage.SelectedValueIndex := 0;
  InvitationPage := CreateInputQueryPage(ModePage.ID, 'Add this VM to your desktop', 'Paste the private setup code from Add machine',
    'Approve enrollment to your self-hosted relay with valid HTTPS. New setup codes connect automatically to the originating desktop. Legacy installation invitations remain supported. Nothing is sent in process arguments or setup logs.');
  InvitationPage.Add('Private setup code (or legacy installation invitation):', True);
  ReadOnlyCheck := TNewCheckBox.Create(InvitationPage);
  ReadOnlyCheck.Parent := InvitationPage.Surface;
  ReadOnlyCheck.Top := InvitationPage.Edits[0].Top + InvitationPage.Edits[0].Height + ScaleY(24);
  ReadOnlyCheck.Width := InvitationPage.SurfaceWidth;
  ReadOnlyCheck.Caption := 'Monitoring only (disable administration, protection and schedules)';
  ReadOnlyCheck.Checked := True;
#ifdef UnsignedPreview
  ReadOnlyCheck.Enabled := False;
#endif
  if CmdBootstrap then begin
    ReadOnlyCheck.Checked := True;
    ReadOnlyCheck.Enabled := False;
  end;
  CodePage := CreateCustomPage(InvitationPage.ID, 'Private expiring connection code', 'Copy this code into the desktop app; do not share it publicly');
  CodeLabel := TNewStaticText.Create(CodePage);
  CodeLabel.Parent := CodePage.Surface;
  CodeLabel.SetBounds(0, 0, CodePage.SurfaceWidth, ScaleY(85));
  CodeLabel.AutoSize := False;
  CodeLabel.WordWrap := True;
  CodeMemo := TNewMemo.Create(CodePage);
  CodeMemo.Parent := CodePage.Surface;
  CodeMemo.SetBounds(0, ScaleY(90), CodePage.SurfaceWidth, ScaleY(80));
  CodeMemo.ReadOnly := True;
  CodeMemo.WordWrap := True;
  CopyButton := TNewButton.Create(CodePage);
  CopyButton.Parent := CodePage.Surface;
  CopyButton.SetBounds(0, ScaleY(182), ScaleX(150), ScaleY(28));
  CopyButton.Caption := 'Copy private code';
  CopyButton.OnClick := @CopyCode;
  RefreshButton := TNewButton.Create(CodePage);
  RefreshButton.Parent := CodePage.Surface;
  RefreshButton.SetBounds(ScaleX(165), ScaleY(182), ScaleX(150), ScaleY(28));
  RefreshButton.Caption := 'Generate fresh code';
  RefreshButton.OnClick := @RefreshCode;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := CmdBootstrap or ((PageID = ModePage.ID) and not Registered) or
    ((PageID = InvitationPage.ID) and Registered) or
    ((PageID = CodePage.ID) and not PairOnly);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ModePage.ID then begin
    PairOnly := ModePage.SelectedValueIndex = 0;
    if PairOnly then begin
      if not InvokeHelper(InstalledRelease + '\agent\RDPMonitorAgent.exe', 'pair --session ' + Session) then begin
        MsgBox(ReadResult('status.txt'), mbError, MB_OK);
        Result := False;
      end else ShowCode;
    end;
  end;
  if (CurPageID = InvitationPage.ID) and not Registered then begin
    if (Length(Trim(InvitationPage.Values[0])) < 60) or (Length(InvitationPage.Values[0]) > 8192) then begin
      MsgBox('Paste a complete private rdpmonitor://setup code (or legacy rdpmonitor://install invitation).', mbError, MB_OK);
      Result := False;
    end;
#ifndef UnsignedPreview
    if Result and not ReadOnlyCheck.Checked then
      Result := MsgBox('Authorize administration on this agent? Enrolled owners may explicitly perform Windows management operations. Setup itself will not change RDP, firewall policy or accounts.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
#endif
  end;
  if (CurPageID = CodePage.ID) and PairOnly then begin
    FinishedPairing := True;
    WizardForm.Close;
    Result := False;
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = CodePage.ID) and PairOnly then begin
    WizardForm.NextButton.Caption := SetupMessage(msgButtonFinish);
    WizardForm.BackButton.Visible := False;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var Arguments: String;
begin
  Result := '';
  if PairOnly then begin Result := 'Pairing does not install files.'; exit; end;
  if not Registered and not CmdBootstrap then
    if not SaveStringToFile(SessionDir + '\invitation.txt', UTF8Encode(Trim(InvitationPage.Values[0])), False) then begin
      Result := 'Cannot write protected invitation exchange.'; exit;
    end;
  InvitationPage.Values[0] := '';
  Arguments := 'stage --session ' + Session + ' --version {#ReleaseVersion}';
#ifdef UnsignedPreview
  Arguments := Arguments + ' --unsigned-preview';
#endif
  if CmdBootstrap then Arguments := Arguments + ' --cmd-bootstrap';
#ifdef GuestOnly
  Arguments := Arguments + ' --guest-only';
#endif
  if not InvokeHelper(Bootstrap, Arguments) then Result := ReadResult('status.txt');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var Arguments: String;
begin
  if CurStep = ssPostInstall then begin
    InstalledRelease := ExpandConstant('{app}\releases\{#ReleaseVersion}');
    Arguments := 'install --session ' + Session + ' --package ' + Quote(InstalledRelease);
#ifdef UnsignedPreview
    Arguments := Arguments + ' --unsigned-preview --preview-consent --read-only';
#else
    Arguments := Arguments + ' --publisher-thumbprint {#PublisherThumbprint}';
    if ReadOnlyCheck.Checked then Arguments := Arguments + ' --read-only';
#endif
#ifdef GuestOnly
    Arguments := Arguments + ' --guest-only';
#endif
    if CmdBootstrap then Arguments := Arguments + ' --cmd-bootstrap --read-only';
    if not InvokeHelper(InstalledRelease + '\agent\RDPMonitorAgent.exe', Arguments) then begin
      PostInstallFailed := True;
      if CmdBootstrap then exit;
      WizardForm.FinishedHeadingLabel.Caption := 'Setup requires attention';
      WizardForm.FinishedLabel.Caption := ReadResult('status.txt') + #13#10#13#10 +
        'The runtime was installed, but relay setup or pairing did not complete. Do not treat this as a completed connection.' + #13#10#13#10 +
        'Rerun this installer to repair the same release or generate a fresh code for advanced Connect with code. If registration was rejected, discard the pending setup and create a new setup code in Add machine. Identity and saved data are preserved.';
      WizardForm.FinishedLabel.Visible := True;
      WizardForm.FinishedLabel.AutoSize := False;
      WizardForm.FinishedLabel.Height := WizardForm.FinishedPage.ClientHeight - WizardForm.FinishedLabel.Top - ScaleY(8);
      exit;
    end;
    if CmdBootstrap then exit;
    ShowCode;
    // The actual completion surface is the native finish page, retaining a copyable
    // memo and refresh action rather than placing credentials in a log or URL.
    CodeLabel.Parent := WizardForm.FinishedPage;
    CodeMemo.Parent := WizardForm.FinishedPage;
    CopyButton.Parent := WizardForm.FinishedPage;
    RefreshButton.Parent := WizardForm.FinishedPage;
    // Reuse the native finish-body origin/width; custom-page coordinates would
    // overlap the finish heading or bitmap after reparenting.
    CodeLabel.SetBounds(WizardForm.FinishedLabel.Left, WizardForm.FinishedLabel.Top,
      WizardForm.FinishedLabel.Width, ScaleY(85));
    CodeMemo.SetBounds(CodeLabel.Left, CodeLabel.Top + CodeLabel.Height + ScaleY(8),
      CodeLabel.Width, ScaleY(80));
    CopyButton.SetBounds(CodeLabel.Left, CodeMemo.Top + CodeMemo.Height + ScaleY(12), ScaleX(150), ScaleY(28));
    RefreshButton.SetBounds(CodeLabel.Left + ScaleX(165), CopyButton.Top, ScaleX(150), ScaleY(28));
    WizardForm.FinishedLabel.Visible := False;
    if ReadResult('automatic.txt') = '1' then
      WizardForm.FinishedHeadingLabel.Caption := 'Installed: ready for your desktop'
    else WizardForm.FinishedHeadingLabel.Caption := 'Installed: private connection code';
  end;
end;

procedure CancelButtonClick(CurPageID: Integer; var Cancel, Confirm: Boolean);
begin
  if FinishedPairing then begin Cancel := True; Confirm := False; end;
end;

procedure DeinitializeSetup;
begin
  ClearCommandEnvironment;
  if Prepared then
    if not InvokeHelper(Bootstrap, 'cleanup --session ' + Session) then
      DelTree(SessionDir, True, True, True);
end;

function InitializeUninstall: Boolean;
begin
  Result := MsgBox('Remove RDPMonitor services and packaged files? Machine identity, enrolled devices, data, backups and all firewall/protection policy are retained. Relay route revocation is a separate action in the desktop app.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
  if Result then begin
    Result := InvokeHelper(ExpandConstant('{app}\releases\{#ReleaseVersion}\agent\RDPMonitorAgent.exe'),
      'remove --package ' + Quote(ExpandConstant('{app}\releases\{#ReleaseVersion}')));
    if not Result then MsgBox('Service removal failed. Files will not be removed. Resolve the installed release/signature/service prerequisite first.', mbError, MB_OK);
  end;
end;

function GetCustomSetupExitCode: Integer;
begin
  if PostInstallFailed then Result := 42 else Result := 0;
end;
