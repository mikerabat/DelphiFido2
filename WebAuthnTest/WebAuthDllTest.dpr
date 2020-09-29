program WebAuthDllTest;

uses
  Forms,
  ufrmMain in 'ufrmMain.pas' {frmWebAuthnTest},
  webauthn in '..\webauthn.pas',
  authData in '..\authData.pas',
  winCryptRandom in '..\winCryptRandom.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TfrmWebAuthnTest, frmWebAuthnTest);
  Application.Run;
end.
