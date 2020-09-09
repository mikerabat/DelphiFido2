library fidoWebauthn;

uses
  madExcept,
  WebBroker,
  HTTPD2 in 'HTTPD2.pas',
  ApacheTwoApp in 'ApacheTwoApp.pas',
  ApacheTwoHTTP in 'ApacheTwoHTTP.pas',
  uWebAuth in 'uWebAuth.pas' {modWebAuth: TWebModule},
  Fido2 in '..\Fido2.pas',
  Fido2dll in '..\Fido2dll.pas',
  Fido2Json in '..\Fido2Json.pas',
  windows,
  classes,
  superobject,
  authData in '..\authData.pas',
  cbor in 'D:\DelphiCBOR\cbor.pas';

{.$R *.res}

{$E so}
{$LIBPREFIX 'mod_'}

exports
  apache_module name 'fido2_module';
begin
  Application.Initialize;
  Application.CreateForm(TmodWebAuth, modWebAuth);
  Application.Run;
end.
