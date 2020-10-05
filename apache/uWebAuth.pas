// ###################################################################
// #### This file is part of the mathematics library project, and is
// #### offered under the licence agreement described on
// #### http://www.mrsoft.org/
// ####
// #### Copyright:(c) 2019, Michael R. . All rights reserved.
// ####
// #### Unless required by applicable law or agreed to in writing, software
// #### distributed under the License is distributed on an "AS IS" BASIS,
// #### WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// #### See the License for the specific language governing permissions and
// #### limitations under the License.
// ###################################################################

// interface unti for the apache webbroker interface.

unit uWebAuth;

interface

uses SysUtils, Classes, {$IF CompilerVersion >= 23.0} Web.HTTPApp {$ELSE} HTTPApp {$ENDIF},
     authData, superobject, WebauthnUtil, Fido2, winCryptRandom;

type
  TResponseHeaderType = (rtJSON, rtPNG, rtHTML, rtPDF, rtCSV, rtXML, rtBinary, rtZip, rtExe);

type
  TmodFidoWebauthn = class(TWebModule)
    procedure WebModuleCreate(Sender: TObject);
    procedure modWebAuthitEnrollAction(Sender: TObject; Request: TWebRequest;
      Response: TWebResponse; var Handled: Boolean);
    procedure modWebAuthwaEnrollVerifyAction(Sender: TObject;
      Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
    procedure modWebAuthwaSettingsAction(Sender: TObject; Request: TWebRequest;
      Response: TWebResponse; var Handled: Boolean);
    procedure modWebAuthwaUserExistsAction(Sender: TObject;
      Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
    procedure modWebAuthwaAssertStartAction(Sender: TObject;
      Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
    procedure modWebAuthwaAssertAction(Sender: TObject; Request: TWebRequest;
      Response: TWebResponse; var Handled: Boolean);
  private
    fRand : IRndEngine;

    // helper functions for the return headers and the parameter extraction
    procedure prepareResponse(Response: TWebResponse;
      const rt: TResponseHeaderType = rtJSon);
    function getStringParam(Request : TWebRequest; const Name,
      defVal: string): string;

    { Private-Deklarationen }
  public
    { Public-Deklarationen }
  end;

var modFidoWebauthn: TmodFidoWebauthn;

implementation

uses Fido2Dll, cbor, Windows;

{$R *.dfm}

procedure TmodFidoWebauthn.prepareResponse(Response: TWebResponse; const rt: TResponseHeaderType = rtJSon);
begin
     Response.SetCustomHeader('Pragma','no-cache');
     Response.SetCustomHeader('Cache-Control','no-store, no-cache, must-revalidate');

     // Response.SetCustomHeader('Access-Control-Allow-Origin', 'http://localhost:63342');  // WebStorm
     Response.SetCustomHeader('Access-Control-Allow-Origin', '*');  // Maybe too permissive
     // See also https://stackoverflow.com/questions/14003332/access-control-allow-origin-wildcard-subdomains-ports-and-protocols

     case rt of
       rtJSON:  Response.ContentType := 'application/json; charset=UTF-8';
       rtPNG:   Response.ContentType := 'image/png';
       rtHTML:  Response.ContentType := 'text/html; charset=UTF-8';
       rtPDF:   Response.ContentType := 'application/pdf';
       rtCSV:   begin
                     Response.CustomHeaders.Clear;
                     Response.ContentType := 'text/comma-separated-values; charset=UTF-8';
                end;
       rtXML:   Response.ContentType := 'text/xml; charset=UTF-8';
       rtBinary:Response.ContentType := 'application/octet-stream';
       rtZip:   Response.ContentType := 'application/zip';
     end;
end;

procedure TmodFidoWebauthn.WebModuleCreate(Sender: TObject);
var fidoSrv : TFidoServer;
begin
     // fill fido server properties
     fidoSrv := FidoServer;
     fidoSrv.RelyingParty := 'fidotest.com';
     fidoSrv.RelyingPartyId := 'fidotest.com';
     fidoSrv.AttestType := atDirect;
     fidoSrv.UserVerification := True;
     fidoSrv.RequireResidentKey := False;

     // prepare random generator
     fRand := CreateWinRndObj;
     fRand.Init(0);
end;

function TmodFidoWebauthn.getStringParam(Request : TWebRequest;
  const Name, defVal: string): string;
var qryParams : TStrings;
    cntParams : TStrings;
begin
     qryParams := Request.QueryFields;
     cntParams := Request.ContentFields;
     if QryParams.IndexOfName(Name) >= 0
     then
         Result := QryParams.Values[Name]
     else if CntParams.IndexOfName(Name) >= 0
     then
         Result := CntParams.Values[Name]
     else
         Result := defVal;
end;

procedure TmodFidoWebauthn.modWebAuthitEnrollAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var uName, displName : string;
    user : TFidoUserStartRegister;
    obj : ISuperObject;
begin
     Handled := True;
     prepareResponse(Response);

     uName := getStringParam(Request, 'uname', '');
     displName := getStringParam(Request, 'realname', '');

     if (uName = '') then
     begin
          response.Content := '{"result":1,"msg":"No user name detected"}';
          exit;
     end;

     // ###########################################
     // #### After extraction of the params prepare the response
     user := TFidoUserStartRegister.Create( uName, displName, fRand );
     try
        if not user.CheckUser( uname )
        then
            obj := so('{"result":2,"msg":"User already registered"}')
        else
        begin
             // save the challenge to db or files
             user.SaveChallenge;

             // prepare response
             obj := user.ToJson;
        end;
        Response.Content := obj.AsJSon;
     finally
            user.Free;
     end;
end;

function Base64Fixup(base64Str: string): string;
var sFixup : string;
    i : integer;
begin
     // url encoding
     sFixup := stringReplace(base64Str, '+', '-', [rfReplaceAll]);
     sFixup := StringReplace(sfixup, '/', '_', [rfReplaceAll]);

     // strip the '='
     i := Length(sFixup);
     while (i > 0) and (sfixup[i] = '=') do
     begin
          delete(sFixup, i, 1);
          dec(i);
     end;

     Result := sFixup;
end;

procedure TmodFidoWebauthn.modWebAuthwaAssertAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var s : string;
    err : ISuperObject;
begin
     prepareResponse(Response);

     try
        with TFidoUserAssert.Create(fRand) do
        try
           if VerifyAssert(Request.Content, s) then
              OutputDebugString('Successfully logged in');

           Response.Content := s;
        finally
               Free;
        end;
     except
           on E : Exception do
           begin
                err := SO;
                err.I['err'] := 1;
                err.S['msg'] := 'An error occured: ' + E.Message;

                Response.Content := err.AsJSon;
           end;

     end;
end;

procedure TmodFidoWebauthn.modWebAuthwaAssertStartAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var err : ISuperObject;
begin
     prepareResponse(Response);

     try
        with TFidoUserAssert.Create(fRand) do
        try
           Response.Content := StartAssertion(getStringParam(Request, 'uname', ''));
        finally
               Free;
        end;
     except
           on E : Exception do
           begin
                err := SO;
                err.I['err'] := 1;
                err.S['msg'] := 'An error occured: ' + E.Message;

                Response.Content := err.AsJSon;
           end;

     end;
end;

procedure TmodFidoWebauthn.modWebAuthwaEnrollVerifyAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var err : ISuperObject;
begin
     prepareResponse(Response);

     try
        // ###########################################
        // #### Run the verification process on the content data
        with TFidoUserRegisterVerify.Create do
        try
           Response.Content := VerifyAndSaveCred( Request.Content );
        finally
               Free;
        end;
     except
           on E : Exception do
           begin
                err := SO;
                err.I['err'] := 1;
                err.S['msg'] := 'An error occured: ' + E.Message;

                Response.Content := err.AsJSon;
           end;

     end;
end;

procedure TmodFidoWebauthn.modWebAuthwaSettingsAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
begin
     prepareResponse(Response);

     Response.Content := FidoServer.ToJSON.AsJSon;
end;

procedure TmodFidoWebauthn.modWebAuthwaUserExistsAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var uname : string;
begin
     prepareResponse(Response, rtJSON);

     uName := getStringParam(Request, 'uname', '');
     if (uName = '') then
     begin
          response.Content := '{"result":1,"msg":"No user name detected"}';
          exit;
     end;

     if FidoDataHandler.IsAlreadRegistered(uname)
     then
         response.Content := '{"result":2,"msg":"User already exists"}'
     else
         Response.Content := '{"result":0,"msg":"User does not exist"}';
end;

procedure fidoLogHandler(msg : PAnsiChar); cdecl;
begin
     OutputDebugStringA( msg );
end;

initialization
  fido_init(cFidoInitDebug);
  fido_set_log_handler(fidoLogHandler);

end.
