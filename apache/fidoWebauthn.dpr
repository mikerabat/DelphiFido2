library fidoWebauthn;

uses
  {$IF CompilerVersion >= 23.0}
  {$IFDEF MSWINDOWS}
  Winapi.ActiveX,
  System.Win.ComObj,
  {$ENDIF }
  Web.WebBroker,
  Web.ApacheApp,
  Web.HTTPD24Impl,
  {$else}
  WebBroker,
  HTTPApp,
  HTTPD2,
  ApacheTwoApp,
  ApacheTwoHTTP,
  {$IFEND}
  uWebAuth in 'uWebAuth.pas' {modFidoWebauthn: TWebModule},
  Fido2 in '..\Fido2.pas',
  Fido2dll in '..\Fido2dll.pas',
  windows,
  classes,
  superobject,
  authData in '..\authData.pas',
  cbor in 'D:\DelphiCBOR\cbor.pas',
  FileFidoDataHandling in '..\FileFidoDataHandling.pas',
  winCryptRandom in '..\winCryptRandom.pas',
  WebauthnHandler in '..\WebauthnHandler.pas',
  OpenSSL1_1ForWebauthn in '..\OpenSSL1_1ForWebauthn.pas';

{.$R *.res}

{$E so}
{$LIBPREFIX 'mod_'}

{$IF CompilerVersion < 23}
exports
  apache_module name 'fidoWebauth_module';
{$ELSE}
var apache_module : TApacheModuleData;

exports
  apache_module name 'fidoWebauth_module';
{$IFEND}

begin
{$IF CompilerVersion >= 23.0}
  CoInitFlags := COINIT_MULTITHREADED;
  Web.ApacheApp.InitApplication(@apache_module);
{$ELSE}
  Application.Initialize;
{$IFEND}
  Application.CreateForm(TmodFidoWebauthn, modFidoWebauthn);
  Application.Run;
end.
