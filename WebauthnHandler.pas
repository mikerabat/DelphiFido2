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

// this unit translates JSON formatted data to and from the Fido2 objects.
// it's based on the the Delphi Json Library "superobject" from
// https://github.com/hgourvest/superobject


// ###########################################
// #### These utility classes can be used to interface the webauthn.js files
// #### provided with this project
// ###########################################
unit WebauthnHandler;

interface

uses SysUtils, Fido2, SuperObject, cbor, authData, winCryptRandom;


type
  EFidoDataHandlerException = class(Exception);

// ###########################################
// #### User registration handling
type
  TFidoUserStartRegister = class;

  IFidoDataHandling = interface
  ['{B3AF2050-BB60-46DC-8BBA-9102076F2480}']
    procedure CleanupPendingChallenges(aChallenge : string = '');
    function IsAlreadRegistered( uname : string ) : boolean; overload;
    function IsAlreadRegistered( uname : string; var credIDFN : string ) : boolean; overload;

    function IsChallengeInitiated( challenge : string; var data : ISuperObject ) : boolean;
    function CredentialDataFromId(credId: string; var data : string): TFidoCredentialFmt;

    procedure SaveUserInitChallenge( user : TFidoUserStartRegister );
    function SaveCred( fmt : string; id : string; userHandle : string; challenge : string; cred : TFidoCredVerify; authData : TAuthData ) : boolean;

    function CredToUser(credId: string; var uname: string): boolean;
    procedure SaveAssertChallengeData( challenge : ISuperObject );
    function LoadAssertChallengeData( challenge : string ) : ISuperObject;
    function CheckSigCounter(credId: string; authData: TAuthData): boolean;
  end;

  // base handler class for all the objects
  // the function FidoDataHandler returns either the local handler inserted by setHandler
  // or the one set global one if threading is no issue
  TBaseFidoDataHandler = class(TObject)
  private
    fHandler : IFidoDataHandling;
  protected
    function FidoDataHandler : IFidoDataHandling;
  public
    procedure SetHandler( handler : IFidoDataHandling );
  end;

// ###########################################
// #### Base properties required by the server
  TFidoAttestationType = (atDirect, atNone, atIndirect);
  TFidoServer = class(TObject)
  private
    fRelID: string;
    fTimeOut: integer;
    fRelParty: string;
    fAttestationType : TFidoAttestationType;
    fResidentKey : boolean;
    fUserVerification : boolean;
    fMinAttesType: TFidoAttestationType;
  public
    property RelyingParty : string read fRelParty write fRelParty;
    property RelyingPartyId : string read fRelID write fRelId;
    property AttestType : TFidoAttestationType read fAttestationType write fAttestationType;

    // Although we want direct attestation the client can downgrad. e.g. we want direct but
    // webauthn over a third party e.g. PC -> passkey on an Iphone. Returns none
    property MinAllowedAttestation : TFidoAttestationType read fMinAttesType write fMinAttesType;

    property TimeOut : integer read fTimeOut write fTimeOut;
    property RequireResidentKey : boolean read fResidentKey write fResidentKey;
    property UserVerification : boolean read fUserVerification write fUserVerification;

    function RPIDHash : TFidoSHA256Hash;

    function ToJSON : ISuperObject;

    constructor Create;
  end;

// ###########################################
// #### Enrollment

  TFidoUserStartRegister = class(TBaseFidoDataHandler)
  private
   const cNoUserId : TFidoUserId = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0);
         cNoChallange : TFidoChallenge = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0);
  private
    fDisplName: string;
    fUserName: string;
    fUserid : TFidoUserId;
    fChallenge : TFidoChallenge;
    fRand : IRndEngine;

    procedure InitUserId;
    procedure InitChallenge;
  public
    property UserName : string read fUserName write fUserName;
    property UserDisplName : string read fDisplName write fDisplName;

    property UserId : TFidoUserId read fUserId write fUserId;
    property Challenge : TFidoChallenge read fChallenge write fChallenge;

    function ToJson : ISuperObject;
    procedure SaveChallenge;

    function CheckUser( uname : string ) : boolean;

    constructor Create( UName, displName : string; rand : IRndEngine);
  end;

type
  TAttestDecodeResult = (tsFailed, tsFullAttestation, tsSurrogateAttestation);
  TCustomFidoVerify = class(TBaseFidoDataHandler)
  protected
    function DecodeAttestationObj( attestStr : string; var alg : integer;
                                   var fmt : string; var sig, authData, x5c : TBytes ) : boolean;
  end;

// #### Class to verify the credentials created from the initial starting registering process
type
  TFidoUserRegisterVerify = class(TCustomFidoVerify)
  public
    function VerifyAndSaveCred( credJson : string; var jsonRes, uname : string ) : boolean;
  end;

// ###########################################
// #### Assertion
type
  TFidoUserAssert = class(TCustomFidoVerify)
  private
    fRand : IRndEngine;
    function CheckCredentials(userHandle: string; origChallenge: ISuperObject;
      var credId: string): boolean;

    function CoseHashAlgStr( regAuthData : TAuthData ) : string;
    function VerifyOKP( signature, sigBase : TBytes; regAuthData : TAuthData ) : boolean;
    function VerifyEC2( signature, sigBase : TBytes; regAuthData : TAuthData ) : boolean;
    function VerifyRSA( signature, sigBase : TBYtes; regAuthData : TAuthData ) : boolean;
  public
    function StartAssertion( uname : string ) : string;
    function VerifyAssert( assertionStr : string; var resStr : string; var uname : string ) : boolean;

    constructor Create(rand : IRndEngine);
  end;

function FidoServer : TFidoServer;
function SHA256FromBuf( buf : PByte; len : integer ) : TFidoSHA256Hash;
function Hash( alg : AnsiString; buf : PByte; len : integer ) : TBytes;

procedure SetDefFidoDataHandler( aHandler : IFidoDataHandling );
function GetDefFidoDataHandler : IFidoDataHandling;

implementation

uses syncObjs, strUtils, Classes,
     Fido2dll, Windows,
     OpenSSL1_1ForWebauthn;



var locServer : TFidoServer = nil;
    locDataHandler : IFidoDataHandling = nil;
    cs : TCriticalSection;


procedure SetDefFidoDataHandler( aHandler : IFidoDataHandling );
begin
     locDataHandler := aHandler;
end;

function GetDefFidoDataHandler : IFidoDataHandling;
begin
     Assert( Assigned(locDataHandler), 'Data handler not assigend - call SetFidoDataHandler at first');
     Result := locDataHandler;
end;

function FidoDataHandler : IFidoDataHandling;
begin
     Assert( Assigned(locDataHandler), 'Data handler not assigend - call SetFidoDataHandler at first');
     Result := locDataHandler;
end;

function FidoServer : TFidoServer;
begin
     cs.Enter;
     try
        Result := locServer;
        if not Assigned(Result) then
        begin
             Result := TFidoServer.Create;
             locServer := Result;
        end;
     finally
            cs.Leave;
     end;
end;

function CredentialToJSon( cred : TFidoCredCreate ) : string;
var clIDHash : TFidoSHA256Hash;
    json : ISuperObject;
    chArr : TSuperArray;
    i : Integer;
    obj : ISuperObject;
begin
     json := SO;

     // ###############################################
     // #### Challange
     clIDHash := cred.ClientDataHash;
     obj := SO;
     chArr := obj.AsArray;
     for i := 0 to Length(clIDHash) - 1 do
         chArr.Add( TSuperObject.Create(clIDHash[i]) );
     json.O['Challange'] := obj;

     Result := json.AsJSon;
end;

{ TFidoServer }

constructor TFidoServer.Create;
begin
     inherited Create;

     fRelID := 'fidotest.com';
     fRelParty := 'fidotest.com';
     fAttestationType := atNone;
     fMinAttesType := atNone;
     fResidentKey := True;

     fTimeOut := 60000;
end;

function TFidoServer.RPIDHash: TFidoSHA256Hash;
var buf : UTF8String;
begin
     buf := UTF8String( RelyingPartyId );
     FillChar(Result, sizeof(Result), 0);
     if buf <> '' then
        Result := SHA256FromBuf( @buf[1], Length(buf));
end;

function TFidoServer.ToJSON: ISuperObject;
begin
     // an array of the 3 standard encryption algorithm the fido dll supports
     // COSE_ES256	= -7;
     // COSE_EDDSA	= -8;
     // COSE_RS256	= -257;
     Result := SO('{"publicKey":{"pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-257,"type":"public-key"},{"alg":-8,"type":"public-key"}]}}');
     Result.I['publicKey.Timeout'] := fTimeOut;

     Result.S['publicKey.rp.id'] := fRelID;
     Result.S['publicKey.rp.name'] := fRelParty;

     Result.S['publicKey.authenticatorSelection.authenticatorAttachment'] := 'cross-platform'; // fido dll -> cross platform we don't support TPM or others yet...
     case fAttestationType of
       atDirect: Result.S['publicKey.attestation'] := 'direct';
       atNone: Result.S['publicKey.attestation'] := 'none';
       atIndirect: Result.S['publicKey.attestation'] := 'indirect';
     end;

     Result.B['publicKey.authenticatorSelection.requireResidentKey'] := fResidentKey;
     // todo: preferred missing
     Result.S['publicKey.authenticatorSelection.userVerification'] := ifthen( fUserVerification, 'required', 'discouraged');
end;

{ TFidoUserStartRegister }

function TFidoUserStartRegister.CheckUser(uname: string): boolean;
begin
     Result := not FidoDataHandler.IsAlreadRegistered(uname);
end;

constructor TFidoUserStartRegister.Create(UName, displName: string; rand : IRndEngine);
begin
     fRand := rand;
     fDisplName := displName;
     fUserName := UName;

     if fDisplName = '' then
        fDisplName := fUserName;

     // create a new cahllange and user id
     InitChallenge;
     InitUserId;

     inherited Create;
end;

procedure TFidoUserStartRegister.InitChallenge;
var i : integer;
begin
     for i := 0 to Length(fchallenge) - 1 do
         fChallenge[i] := fRand.Random;
end;

procedure TFidoUserStartRegister.InitUserId;
var i : integer;
begin
     // first byte of the random user ID shall not be one or zero
     // see: https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/User_Handle.html
     repeat
           fUserid[0] := fRand.Random;
     until fUserid[0] > 1;

     for i := 1 to High(fUserid) do
         fUserid[i] := fRand.Random;
end;

procedure TFidoUserStartRegister.SaveChallenge;
begin
     assert( Assigned(locDataHandler), 'Error no data handler assigned');

     locDataHandler.SaveUserInitChallenge( self );
end;

function TFidoUserStartRegister.ToJson: ISuperObject;
var server : ISuperObject;
begin
     // check if the user id and challenge is initialized
     if CompareMem( @fUserid[0], @cNoUserId[0], sizeof(fUserid)) then
        raise EFidoPropertyException.Create('No User ID created');

     // build result
     Result := SO('{"publicKey":{}}');

     Result.S['publicKey.user.displayName'] := fDisplName;
     Result.S['publicKey.user.name'] := fUserName;
     Result.S['publicKey.user.id'] := Base64URLEncode( PByte( @fUserid[0] ), sizeof(fUserid) );
     Result.S['publicKey.challenge'] := Base64URLEncode( PByte( @fChallenge[0] ), sizeof(fChallenge) );

     server := FidoServer.ToJSON;
     Result.Merge(server);
end;

function Hash( alg : AnsiString; buf : PByte; len : integer ) : TBytes;
var ctx : PEVP_MD_CTX;
    aHashAlg : PEVP_MD;
begin
     //if not IdSSLOpenSSLHeaders.Load then
//        raise Exception.Create('Failed to load Openssl lib');
     aHashAlg := EVP_get_digestbyname(PAnsiChar(alg));
     ctx := EVP_MD_CTX_create;
     EVP_DigestInit_ex(ctx, aHashAlg, nil);
     SetLength(Result, EVP_MD_size(aHashAlg));
     EVP_DigestUpdate(ctx, buf, len);
     EVP_DigestFinal_ex(ctx, @Result[0], nil);
     EVP_MD_CTX_Free(ctx);
end;

function SHA256FromBuf( buf : PByte; len : integer ) : TFidoSHA256Hash;
var ahash : TBytes;
begin
      aHash := Hash('sha256', buf, len);
      assert(Length(aHash) = Length(Result), 'Wrong result len');
      Move(aHash[0], Result, Length(aHash));
end;

{ TCustomFidoVerify }

function TCustomFidoVerify.DecodeAttestationObj(attestStr: string;
  var alg: integer; var fmt: string; var sig, authData, x5c: TBytes): boolean;
var cborItem : TCborMap;
    restBuf : TBytes;
    aName : string;
    attStmt : TCborMap;
    i, j : integer;
begin
     Result := False;

     // https://medium.com/webauthnworks/verifying-fido2-packed-attestation-a067a9b2facd
     // the link shows how to verify the attestationobj with and without the attStmt object

     // attestation object is a cbor encoded raw base64url encoded string
     cborItem := TCborDecoding.DecodeBase64UrlEx(attestStr, restBuf) as TCborMap;


     // check if there is data left indicating bad cbor format
     if Length(restBuf) <> 0  then
        exit;

     if not Assigned(cborItem) then
        exit;
     try
        alg := 0;
        fmt := '';
        sig := nil;
        authData := nil;
        x5c := nil;

        for i := 0 to cborItem.Count - 1 do
        begin
             // check cbor map name format
             if not (cborItem.Names[i] is TCborUtf8String) then
                exit;

             aName := String((cborItem.Names[i] as TCborUtf8String).Value);
             if SameText(aName, 'attStmt') then
             begin
                  attStmt := cborItem.Values[i] as TCborMap;
                  for j := 0 to attStmt.Count - 1 do
                  begin
                       // elements for full attestation
                       aName := String((attStmt.Names[j] as TCborUtf8String).Value);

                       if SameText(aName, 'alg')
                       then
                           alg := (attStmt.Values[j] as TCborNegIntItem).value
                       else if SameText(aName, 'sig')
                       then
                           sig := (attStmt.Values[j] as TCborByteString).ToBytes
                       else if SameText(aName, 'x5c')
                       then
                           x5c := ((attStmt.Values[j] as TCborArr)[0] as TCborByteString).ToBytes;
                  end;
             end
             else if SameText(aName, 'authData')
             then
                 authData := (cborItem.Values[i] as TCborByteString).ToBytes
             else if SameText(aName, 'fmt')
             then
                 fmt := String( (cborItem.Values[i] as TCborUtf8String).Value );
        end;
     finally
            cborItem.Free;
     end;

     // minimum requirements for full attestation
     // and none attestation
     Result := ( (fmt = 'none') and (authData <> nil) ) or
               ( (fmt = 'packed') and (alg <> 0) and (sig <> nil) and (x5c <> nil) );
end;

{ TFidoUserRegisterVerify }

function TFidoUserRegisterVerify.VerifyAndSaveCred(credJson: string; var jsonRes, uname : string ) : boolean;
var clientData, startData : ISuperObject;
    s : string;
    credentialId : string;
    rawId : TBytes;
    credVerify : TFidoCredVerify;
    sig : TBytes;
    x5c : TBytes;
    authData : TBytes;
    fmt : string;
    alg : integer;
    credFMT : TFidoCredentialFmt;
    authDataObj : TAuthData;
    restBuf : TBytes;
    clientDataStr : RawByteString;
    clientDataHash : TFidoSHA256Hash;
    serverRPIDHash : TFidoSHA256Hash;
    rpIDHash : TFidoRPIDHash;
    credential : ISuperObject;
    clientDataBuf : RawByteString;
    userHandle : string;
begin
     Result := False;
     jsonRes := '{"error":0,"msg":"Error parsing content"}';

     credential := SO(credJSON);
     if not Assigned(credential) then
        exit;

     s := credential.S['response.clientDataJSON'];

     if s = '' then
        exit;

     clientDataBuf := Base64URLDecode( s );

     ClientData := So( String(clientDataBuf) );
     if clientData = nil then
        exit;

     // ###########################################
     // #### Check if the challenge has been initiated and the fields are correct
     if not FidoDataHandler.IsChallengeInitiated(ClientData.S['challenge'], startData) then
     begin
          jsonRes := '{"error":1,"msg":"Client data json parsing error - challenge not initiated"}';

          exit;
     end;

     uname := startData.S['publicKey.user.name'];

     if clientData.S['type'] <> 'webauthn.create' then
     begin
          jsonRes := '{"error":5,"msg":"Client data wrong type"}';
          exit;
     end;

     if Pos(FidoServer.RelyingParty, clientData.S['origin']) = 0 then
     begin
          jsonRes := '{"error":6,"msg":"Wrong origin field provided"}';
          exit;
     end;

     // calculate hash from clientDataJSON
     clientDataStr := Base64URLDecode( credential.S['response.clientDataJSON'] );
     if clientDataStr = '' then
     begin
          jsonRes := '{"error":2,"msg":"Client data json missing"}';

          exit;
     end;

     s := credential.S['response.attestationObject'];
     if s = '' then
        exit;

     // ###########################################
     // #### According to format decode:
     if not DecodeAttestationObj(s, alg, fmt, sig, authData, x5c) then
     begin
          jsonRes := '{"error":2,"msg":"Decoding failed"}';
          exit;
     end;

     if Length(restBuf) > 0 then
        raise Exception.Create('Decoding error - a rest buffer that should not be');

     // decoding seems to have provided somethinge - now check if all fields
     // are there according to the format
     // we support 'none' and 'packed'
     // please note that "none" is not supported by fido2.dll 's fido_veriy procedure!
     // none is actually very weak and no verification is performed. Just the
     // check if proper keys are provided and store them
     if (fmt = 'none') and (FidoServer.MinAllowedAttestation = atNone) then
     begin
          // just check if the correct fields are there there is nothing to verify
          if Length(authData) = 0 then
             raise Exception.Create('Missing authdata');

          authDataObj := TAuthData.Create( authData );
          try
             if not authDataObj.HasPublicKey then
                raise Exception.Create('No Public key provided');
             if not (( authDataObj.PublicKeyAlg = COSE_ES256 ) or (authDataObj.PublicKeyAlg = COSE_EDDSA) or
                     (authDataObj.PublicKeyAlg = COSE_RS256)) then
                raise Exception.Create('Unknown algorithm');

             credentialId := credential.S['rawId'];
             if s = '' then
                raise Exception.Create('No Credential id found');
             rawId := Base64URLDecodeToBytes( s );

             //credential.SaveTo('D:\credtest.json');
             userHandle := credential.S['response.userHandle'];
             if userHandle = '' then
                userHandle := startData.S['publicKey.user.id'];
             Result := FidoDataHandler.SaveCred(fmt, credentialID, userHandle, ClientData.S['challenge'], nil, authDataObj);
          finally
                 authDataObj.Free;
          end;
     end
     else if fmt = 'packed' then
     begin
          // check if anyhing is in place
          if not (( alg = COSE_ES256 ) or (alg = COSE_EDDSA) or (alg = COSE_RS256)) then
             raise Exception.Create('Unknown algorithm');
          if Length(sig) = 0 then
             raise Exception.Create('No sig field provided');
          if Length(x5c) = 0 then
             raise Exception.Create('No certificate');
          if Length(authData) = 0 then
             raise Exception.Create('Missing authdata');

          credentialId := credential.S['rawId'];
          if s = '' then
             raise Exception.Create('No Credential id found');
          rawId := Base64URLDecodeToBytes( s );

          if Length(restBuf) > 0 then
             raise Exception.Create('Damend there is a rest buffer that should not be');

          authDataObj := TAuthData.Create( authData );
          try
             if not authDataObj.UserPresent then
             begin
                  jsonRes := '{"error":3,"msg":"Error: parameter user present not set"}';
                  exit;
             end;

             if authDataObj.UserVerified <> FidoServer.UserVerification then
             begin
                  jsonRes := '{"error":4,"msg":"Error: parameter user verification not set to the default"}';
                  exit;
             end;

             // check rp hash
             rpIDHash := authDataObj.rpIDHash;
             serverRPIDHash := FidoServer.RPIDHash;
             if not CompareMem( @rpIDHash[0], @serverRPIDHash[0], sizeof(rpIDHash)) then
             begin
                  jsonRes := '{"error":7,"msg":"The relying party hash does not match"}';
                  exit;
             end;

             if fmt = 'packed'
             then
                 credFmt := fmFido2
             else if fmt = 'fido-u2f'
             then
                 credFmt := fmU2F
             else if fmt = 'tpm'
             then
                 credFmt := fmTPM
             else
                 credFmt := fmNone;

             // create the client hash that is later used in the verification process
             clientDataHash := SHA256FromBuf( @clientDataStr[1], Length(clientDataStr) );


             // ###########################################
             // #### Now bring the fido dll into action
             credVerify := TFidoCredVerify.Create( TFidoCredentialType(alg), credFmt,
                                                   FidoServer.RelyingPartyId, FidoServer.RelyingParty,
                                                   TBaseFido2Credentials.WebAuthNObjDataToAuthData( authData ),
                                                   x5c, sig,
                                                   FidoServer.RequireResidentKey,
                                                   authDataObj.UserVerified, 0, nil)  ;
             try
                Result := credVerify.Verify(clientDataHash);

                if Result then
                begin
                     credentialId := credential.S['rawId'];

                     // ###########################################
                     // #### save EVERYTHING to a database
                     userHandle := credential.S['response.userHandle'];
                     if userHandle = '' then
                        userHandle := startData.S['publicKey.user.id'];
                     FidoDataHandler.SaveCred(fmt, credentialId, userHandle, ClientData.S['challenge'], credVerify, authDataObj);
                end;
             finally
                    credVerify.Free;
             end;
          finally
                 authDataObj.Free;
          end;
     end
     else
     begin
          jsonRes := '{"error":8,"msg":"unsupported format"}';
          exit;
     end;

     // build result and generate a session
     if Result
     then
         // yeeeha we got it done
         jsonRes := '{"verified":true}'
     else
         jsonRes := '{"verified":false}';

     // cleanup challenge if verification succeeded
     if Result then
        FidoDataHandler.CleanupPendingChallenges(ClientData.S['challenge']);
end;

{ TFidoUserAssert }

function TFidoUserAssert.CoseHashAlgStr(regAuthData: TAuthData): string;
begin
     case regAuthData.PublicKeyAlg of
       -257: Result := 'sha256';
       -258: Result := 'sha384';
       -259: Result := 'sha512';
     -65535: Result := 'sha1';
       -39: Result := 'sha512';
       -38: Result := 'sha384';
       -37: Result := 'sha256';
      -260: Result := 'sha256';
      -261: Result := 'sha512';
        -7: Result := 'sha256';
       -36: Result := 'sha512';
     else
         Result := 'sha256';
     end;
end;

constructor TFidoUserAssert.Create(rand: IRndEngine);
begin
     fRand := rand;

     if not Assigned(fRand) then
        fRand := CreateWinRndObj;

     inherited Create;
end;

function TFidoUserAssert.StartAssertion(uname: string): string;
var res : ISuperObject;
    challenge : TFidoChallenge;
    i: Integer;
    credID : string;
    credObj : ISuperObject;
begin
     credID := '';

     // no user name given -> just create a challenge (maybe a user handle is used)
     if (uname <> '') and not FidoDataHandler.IsAlreadRegistered(uname, credID) then
        exit('{"error":0,"msg":"User not registered"}');

     // create a random challenge
     for i := 0 to Length(challenge) - 1 do
         challenge[i] := fRand.Random;

     res := SO('{"publicKey":{"allowCredentials":[]}}');
     res.S['publicKey.challenge'] := Base64URLEncode(@challenge[0], length(challenge));
     res.I['publicKey.timeout'] := FidoServer.TimeOut;
     res.S['publicKey.rpid'] := FidoServer.RelyingPartyId;
     res.B['publicKey.userVerificaiton'] := FidoServer.UserVerification;

     // return an empty list if no username was provided -> user id required
     if credID <> '' then
     begin
          credObj := SO( '{"type":"public-key"}' );
          credObj.S['id'] := credID;

          res.A['publicKey.allowCredentials'].Add( credObj );
     end;

     res.O['extensions'] := SO('{"txAuthSimple":""}');

     // ###########################################
     // #### Save the challenge for later comparison
     FidoDataHandler.SaveAssertChallengeData( res );
     
     Result := res.AsJSon;
end;


// checks if a user with a given user handle was already registered or
// if credentials can be mapped to a given challenge
function TFidoUserAssert.CheckCredentials(userHandle: string;
  origChallenge: ISuperObject; var credId : string): boolean;
var cred : TSuperArray;
begin
     Result := False;
     if userHandle <> '' then
        Result := FidoDataHandler.IsAlreadRegistered(userHandle, credId);

     if not Result then
     begin
          cred := origChallenge.A['publicKey.allowCredentials'];
          if (cred <> nil) and (cred.Length > 0) then
          begin
               Result := True;
               credId := cred.O[0].S['id'];
          end;
     end;
end;


function TFidoUserAssert.VerifyAssert(assertionStr: string;
  var resStr: string; var uname : string): boolean;
var clientData : ISuperObject;
    userHandle : string;
    sig : TBytes;
    credID : string;
    fmt : TFidoCredentialFmt;
    clientDataStr : RawByteString;
    clientDataHash : TFidoSHA256Hash;
    authDataObj : TAuthData;
    rpIdHash : TFidoRPIDHash;
    serverRPIDHash : TFidoSHA256Hash;
    credFmt : TFidoCredentialFmt;
    assertVerify : TFidoAssertVerify;
    buf : TBytes;
    challenge : TFidoChallenge;
    authData : TBytes;
    origChallenge : ISuperObject;
    selCredId : string;
    res : ISuperObject;
    assertion : ISuperObject;
    credData : string;
    pkStream : TMemoryStream;
    rawPK : RawByteString;
    sigBase : TBytes;
    regAuthData : TAuthData;
    verified : boolean;
begin
     Result := False;
     resStr := '{"error":0,"msg":"Error parsing content"}';

     assertion := SO(assertionStr);
     if not Assigned(assertion) then
        exit;

     clientDataStr := Base64URLDecode( assertion.S['response.clientDataJSON'] );

     if clientDataStr = '' then
        exit;

     ClientData := So( String( clientDataStr ) );
     if clientData = nil then
        exit;

     if clientData.S['type'] <> 'webauthn.get' then
        exit;

     userhandle := assertion.S['response.userHandle'];
     sig := Base64URLDecodeToBytes(assertion.S['response.signature']);
     credId := assertion.S['id'];

     if assertion.S['type'] <> 'public-key' then
        exit;

     // ###########################################
     // #### Load data from the initialization procedure
     origChallenge := FidoDataHandler.LoadAssertChallengeData(clientData.S['challenge']);
     if not Assigned(origChallenge) then
     begin
          resStr := '{"error":1,"msg":"Challenge not initiated"}';
          exit;
     end;

     // create the client hash that is later used in the verification process
     clientDataHash := SHA256FromBuf( @clientDataStr[1], Length(clientDataStr) );

     authData := Base64URLDecodeToBytes(assertion.S['response.authenticatorData']);

     // check if anyhing is in place
     //if not (( alg = COSE_ES256 ) or (alg = COSE_EDDSA) or (alg = COSE_RS256)) then
     //   raise Exception.Create('Unknown algorithm');
     if Length(sig) = 0 then
     begin
          resStr := '{"error":1,"msg":"No sig field provided"}';
          exit;
     end;
     if Length(authData) = 0 then
     begin
          resStr := '{"error":1,"msg":"Missing authdata"}';
          exit;
     end;

     authDataObj := TAuthData.Create( authData );
     try
        OutputDebugString( PChar('Guid: ' + GuidToString(authDataObj.AAUID)) );

        if not CheckCredentials( userHandle, origChallenge, selCredId ) then
        begin
             resStr := '{"error":2,"msg":"Credentials not in user list"}';
             exit;
        end;

        if selCredId <> credID then
        begin
             resStr := '{"error":2,"msg":"Credentials not in user list"}';
             exit;
        end;

        // check user id attached to credential id
        if not FidoDataHandler.CredToUser( credId, uname ) then
        begin
             resStr := '{"error":2,"msg":"Credentials not in user list"}';
             exit;
        end;

        // todo: maybe it's a good idea to check the guid (got from direct attestation)

        if not authDataObj.UserPresent then
        begin
             resStr := '{"error":3,"msg":"Error: parameter user present not set"}';
             exit;
        end;

        if authDataObj.UserVerified <> FidoServer.UserVerification then
        begin
             resStr := '{"error":4,"msg":"Error: parameter user verification not set to the default"}';
             exit;
        end;

        // check rp hash
        rpIDHash := authDataObj.rpIDHash;
        serverRPIDHash := FidoServer.RPIDHash;
        if not CompareMem( @rpIDHash[0], @serverRPIDHash[0], sizeof(rpIDHash)) then
        begin
             resStr := '{"error":6,"msg":"The relying party hash does not match"}';
             exit;
        end;

        credFmt := fmFido2;
        buf := Base64URLDecodeToBytes( clientData.S['challenge'] );

        if Length(buf) <> sizeof(challenge) then
        begin
             resStr := '{"error":5,"msg":"Challange type failed"}';
             exit;
        end;
        move( buf[0], challenge, sizeof(challenge));

        // ###########################################
        // #### check assertion according to initial attestation format
        fmt := FidoDataHandler.CredentialDataFromId(credId, credData);

        if credData = '' then
        begin
             resStr := '{"error":8,"msg":"Credential data not found"}';
             exit;
        end;

        if fmt = fmNone then
        begin
             // ###########################################
             // #### none attestation - check the signature...

             // from https://medium.com/webauthnworks/verifying-fido2-packed-attestation-a067a9b2facd
             // 1: concat authData with clientdatahash  -> signature base
             SetLength(sigBase, Length(clientDataHash) + Length(authData));
             Move(authdata[0], sigBase[0], Length(authData));
             Move(clientDataHash[0], sigBase[Length(authData)], Length(clientDataHash));

             // 2: according to the stored public key verify the given signature
             regAuthData := TAuthData.Create( Base64UrlDecodeToBytes(credData) );

             if not regAuthData.HasPublicKey then
             begin
                  resStr := '{"error":7,"msg":"No public key - surragate attestation not allowed."}';
                  exit;
             end;

             try
                try
                   case regAuthData.KeyType of
                     COSE_KTY_OKP: verified := VerifyOKP( sig, sigBase, regAuthData );
                     COSE_KTY_EC2: verified := VerifyEC2( sig, sigBase, regAuthData );
                     COSE_KTY_RSA: verified := VerifyRSA( sig, sigBase, regAuthData );
                   else
                       resStr := '{"error":7,"msg":"No public key - surragate attestation not allowed."}';
                       exit(False);
                   end;
                except
                      on F : Exception do
                      begin
                           resStr := '{"error":8","msg":"Verification failed badly"}';
                           exit(False);
                      end;

                end;
             finally
                    regAuthData.Free;
             end;

             Result := verified;
             if verified then
             begin
                  res := SO('{"verified":true}');
                  res.S['username'] := uname;
                  resStr := res.AsJSon;
             end
             else
             begin
                  resStr := '{"verified":false}';
             end;
        end
        else
        begin
             // packed, tpm and
             // ###########################################
             // #### Verify with the fido dll
             assertVerify := TFidoAssertVerify.Create;
             try
                assertVerify.RelyingParty := FidoServer.RelyingPartyId;

                // ###########################################
                // #### now get the private key
                clientData := SO(credData);

                rawPK := Base64Decode(clientData.S['cert.pk']);

                pkStream := TMemoryStream.Create;
                try
                   pkStream.WriteBuffer(rawPK[1], Length(rawPK));
                   pkStream.Position := 0;
                   assertVerify.LoadPKFromStream(pkStream);
                finally
                       pkStream.Free;
                end;

                assertVerify.ClientDataHash := TFidoChallenge( clientDataHash );
                assertVerify.Fmt := credFmt;
                if authDataObj.UserVerified
                then
                    assertverify.UserVerification := FIDO_OPT_TRUE
                else
                    assertverify.UserVerification := FIDO_OPT_FALSE;

                if authDataObj.UserPresent
                then
                    assertVerify.UserPresence := FIDO_OPT_TRUE
                else
                    assertVerify.UserPresence := FIDO_OPT_FALSE;

                if assertVerify.Verify( TBaseFido2Credentials.WebAuthNObjDataToAuthData( authData ),
                                        sig )
                then
                begin
                     // check signal counter
                     if not FidoDataHandler.CheckSigCounter( credId, authDataObj ) then
                     begin
                          resStr := '{"error":5,"msg":"Signal counter is too low - maybe cloned?"}';
                          exit;
                     end;
                     res := SO('{"verified":true}');
                     res.S['username'] := uname;
                     resStr := res.AsJSon;
                     Result := True;
                end
                else
                begin
                     resStr := '{"verified":false}';
                end;
             finally
                    assertVerify.Free;
             end;
        end;
     finally
            authDataObj.Free;
     end;
end;

function TFidoUserAssert.VerifyEC2(signature, sigBase: TBytes; regAuthData: TAuthData): boolean;
var x, y : TBytes;
    curve : TBytes;
    signatureBaseHash : TFidoSHA256Hash;
    pkey: PEVP_PKEY;
    sig: PECDSA_SIG;
    psig: Pointer;
    group: PEC_GROUP;
    key: PEC_KEY;
    point: PEC_POINT;
    ctx: PBN_CTX;
    xBN, yBN: PBIGNUM;
begin
     Result := False;
     // from https://medium.com/webauthnworks/verifying-fido2-packed-attestation-a067a9b2facd
     // line 162 to 173
     x := regAuthData.AttestData2;
     y := regAuthData.AttestData3;
     curve := regAuthDAta.AttestData1;

     if (Length(x) = 0) or (Length(y) = 0) or (Length(curve) = 0) then
        exit;

     // Delphi 2010 message
     {$IF CompilerVersion <=23}
     pkey := nil;
     {$IFEND}

     // sha256
     signatureBaseHash := SHA256FromBuf(@sigBase[0], Length(sigBase));

     // ###########################################
     // #### Now the openssl code to verify the signature
     sig := nil;
     key := nil;
     // this function uses only functions from Openssl 1.1 - OpenSSL.Api_11.pas
     // Create a context for arbitrary precision arithmetic
     ctx := BN_CTX_new;
     if ctx = nil then
       raise Exception.Create('Failed to create BN_CTX - Error: ' + IntToSTr(ERR_get_error));

     try
        // Create a new EC_KEY object
        key := EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if key = nil then
           raise Exception.Create('Failed to create EC_KEY - Error: ' + IntToSTr(ERR_get_error));

        try
          // Get the EC_GROUP from the EC_KEY
          group := EC_KEY_get0_group(key);
          if group = nil then
             raise Exception.Create('Failed to get EC_GROUP - Error: ' + IntToSTr(ERR_get_error));

          // Create BIGNUM objects for x and y coordinates
          xBN := BN_bin2bn(@x[0], Length(x), nil);
          yBN := BN_bin2bn(@y[0], Length(y), nil);
          if (xBN = nil) or (yBN = nil) then
             raise Exception.Create('Failed to create BIGNUM - Error: ' + IntToSTr(ERR_get_error));

          try
            // Create an EC_POINT from x and y coordinates
            point := EC_POINT_new(group);
            if point = nil then
               raise Exception.Create('Failed to create EC_POINT - Error: ' + IntToSTr(ERR_get_error));

            try
              if EC_POINT_set_affine_coordinates_GFp(group, point, xBN, yBN, ctx) <> 1 then
                 raise Exception.Create('Failed to set EC_POINT coordinates - Error: ' + IntToSTr(ERR_get_error));

              // Set the EC_POINT as the public key of the EC_KEY
              if EC_KEY_set_public_key(key, point) <> 1 then
                 raise Exception.Create('Failed to set public key - Error: ' + IntToSTr(ERR_get_error));

              // Success: Return the loaded EC_KEY
              pkey := key;
              key := nil;
            finally
                   EC_POINT_free(point);
            end;
          finally
                 BN_free(xBN);
                 BN_free(yBN);
          end;
        finally
               BN_CTX_free(ctx);
        end;
     finally
            if key <> nil then
               EC_KEY_free(key);
     end;
     // ###########################################
     // #### We have the public key loaded -> verify ecdsa
     try
        psig := @Signature[0];
        sig := d2i_ECDSA_SIG(@sig, @psig, Length(Signature));
        if sig = nil then
           raise Exception.Create('[ECDSA] Can''t decode ECDSA signature - Error: ' + IntToSTr(ERR_get_error));
        try
           Result := ECDSA_do_verify(@signatureBaseHash[0], Length(signatureBaseHash), sig, pkey) = 1;
        finally
               ECDSA_SIG_free(sig);
        end;
     finally
            EC_KEY_free(pkey);
     end;
end;

function TFidoUserAssert.VerifyOKP(signature, sigBase: TBytes;
  regAuthData: TAuthData): boolean;
var signatureBaseHash: TBytes;
    key: PEC_KEY;
    x : TBytes;
    xBN : PBIGNUM;
    hashAlg : AnsiString;
begin
     // Delphi 2010 message
     {$IF CompilerVersion <=23}
     Result := False;
     {$IFEND}

     x := regAuthData.AttestData2;
     hashAlg := AnsiString(CoseHashAlgStr(regAuthData));

     // Calculate signatureBaseHash
     signatureBaseHash := Hash( hashAlg, @sigBase[0], Length(sigBase) );

     // Create EC_KEY structure from public key (x coordinate)
     key := EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
     if key = nil then
        raise Exception.Create('Failed to create key');
     try
        xBN := BN_bin2bn(@x[0], Length(x), nil);
        if xBN = nil then
           raise Exception.Create('Failed to convert x part from OKP');
        try
           EC_KEY_set_conv_form(key, POINT_CONVERSION_UNCOMPRESSED); // Set point conversion form
           EC_KEY_set_public_key_affine_coordinates(key, xBN, nil);

           // Verify signature
           Result := ECDSA_verify(0, @signatureBaseHash[0], Length(signatureBaseHash), @signature[0], Length(signature), key) = 1;
        finally
               BN_free(xBN);
        end;
     finally
            // Cleanup
            EC_KEY_free(key);
     end;
end;

function TFidoUserAssert.VerifyRSA(signature, sigBase: TBYtes;
  regAuthData: TAuthData): boolean;
var rsa_pub_key: PRSA;
    aHash: TBytes;
    exponent : TBytes;
    modulos : TBytes;
    eBN, nBN : PBIGNUM;
    hashAlg : AnsiString;
begin
     //let signingScheme = COSERSASCHEME[pubKeyCose.get(COSEKEYS.alg)];
//
//            let key = new NodeRSA(undefined, { signingScheme });
//            key.importKey({
//                n: pubKeyCose.get(COSEKEYS.n),
//                e: 65537,
//            }, 'components-public');
//
//            signatureIsValid = key.verify(signatureBaseBuffer, signatureBuffer)

     Result := False;

     // Load public key
     modulos := regAuthData.AttestData1;
     exponent := regAuthData.AttestData2;

     if (modulos = nil) or (exponent = nil) then
        exit;

     hashAlg := AnsiString(CoseHashAlgStr(regAuthData));
     rsa_pub_key := RSA_new;
     try
        eBN := BN_bin2bn(@exponent[0], Length(exponent), nil);   // we assume that the given exponent is actually 65537
        nBN := BN_bin2bn(@modulos[0], Length(modulos), nil);
        try
           if (eBN = nil) or (nBN = nil) then
              raise Exception.Create('Failed to convert RSA parameters');
           // set modulos and exponent (should be 65537)
           if RSA_set0_key(rsa_pub_key, nBN, eBN, nil) <> 1 then
              raise Exception.Create('Failed to set public RSA key');

           // Compute hash of the message
           ahash := Hash(hashAlg, @sigBase[0], Length(sigBase));

           // verify with the key...
           Result := RSA_verify(NID_sha256, @aHash[0], Length(aHash), @signature[0], Length(signature), rsa_pub_key) = 1;
        finally
               BN_free(eBN);
               BN_free(nBN);
        end;
     finally
            RSA_free(rsa_pub_key);
     end;

     // is this necessary?
     // ERR_remove_thread_state(nil);
end;

{ TBaseFidoDataHandler }

function TBaseFidoDataHandler.FidoDataHandler: IFidoDataHandling;
begin
     Result := fHandler;
     if not Assigned(Result) then
        Result := locDataHandler;
end;

procedure TBaseFidoDataHandler.SetHandler(handler: IFidoDataHandling);
begin
     fHandler := handler;
end;

initialization
  cs := TCriticalSection.Create;

finalization
  locServer.Free;
  cs.Free;

end.
