library fidoWebauthn;

uses
  madExcept,
  WebBroker,
  HTTPD2 in 'HTTPD2.pas',
  ApacheTwoApp in 'ApacheTwoApp.pas',
  ApacheTwoHTTP in 'ApacheTwoHTTP.pas',
  uWebAuth in 'uWebAuth.pas' {modFidoWebauthn: TWebModule},
  Fido2 in '..\Fido2.pas',
  Fido2dll in '..\Fido2dll.pas',
  WebauthnUtil in '..\WebauthnUtil.pas',
  windows,
  classes,
  superobject,
  authData in '..\authData.pas',
  cbor in 'D:\DelphiCBOR\cbor.pas',
  FileFidoDataHandling in '..\FileFidoDataHandling.pas';

{.$R *.res}

{$E so}
{$LIBPREFIX 'mod_'}

exports
  apache_module name 'fido2_module';
begin
  Application.Initialize;
  Application.CreateForm(TmodFidoWebauthn, modFidoWebauthn);
  Application.Run;
end.
