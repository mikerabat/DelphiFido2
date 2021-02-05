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
  {$ENDIF}
  uWebAuth in 'uWebAuth.pas' {modFidoWebauthn: TWebModule},
  Fido2 in '..\Fido2.pas',
  Fido2dll in '..\Fido2dll.pas',
  WebauthnUtil in '..\WebauthnUtil.pas',
  windows,
  classes,
  superobject,
  authData in '..\authData.pas',
  cbor in 'D:\DelphiCBOR\cbor.pas',
  FileFidoDataHandling in '..\FileFidoDataHandling.pas',
  winCryptRandom in '..\winCryptRandom.pas';

{.$R *.res}

{$E so}
{$LIBPREFIX 'mod_'}

{$IF CompilerVersion >= 23.0}
var
  apache_module: TApacheModuleData;
exports
  apache_module name 'fido2_module';
{$ELSE}
exports
  apache_module name 'fido2_module';
{$ENDIF}

begin
{$IF CompilerVersion >= 23.0}
  CoInitFlags := COINIT_MULTITHREADED;
  Web.ApacheApp.InitApplication(@apache_module);
{$ELSE}
  Application.Initialize;
{$ENDIF}
  Application.CreateForm(TmodFidoWebauthn, modFidoWebauthn);
  Application.Run;
end.
