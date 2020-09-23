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
unit WebauthnUtil;

interface

uses SysUtils, Fido2, SuperObject, cbor, authData, RandomEng;


type
  EFidoDataHandlerException = class(Exception);
// ###########################################
// #### Base properties required by the server
type
  TFidoAttestationType = (atDirect, atNone, atIndirect);
  TFidoServer = class(TObject)
  private
    fRelID: string;
    fTimeOut: integer;
    fRelParty: string;
    fAttestationType : TFidoAttestationType;
    fResidentKey : boolean;
    fUserVerification : boolean;
  public
    property RelyingParty : string read fRelParty write fRelParty;
    property RelyingPartyId : string read fRelID write fRelId;
    property AttestType : TFidoAttestationType read fAttestationType write fAttestationType;

    property TimeOut : integer read fTimeOut write fTimeOut;
    property RequireResidentKey : boolean read fResidentKey write fResidentKey;
    property UserVerification : boolean read fUserVerification write fUserVerification;

    function RPIDHash : TFidoSHA256Hash;

    function ToJSON : ISuperObject;

    constructor Create;
  end;


type
  TFidoUserStartRegister = class(TObject)
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
    fRand : TRandomGenerator;

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

    constructor Create( UName, displName : string; rand : TRandomGenerator);
  end;

type
  TCustomFidoVerify = class(TObject)
  protected
    function DecodeAttestationObj( attestStr : string; var alg : integer;
                                   var fmt : string; var sig, authData, x5c : TBytes ) : boolean;

  end;
// ###########################################
// #### Class to verify the credentials created from the initial starting registering process
type
  TFidoUserRegisterVerify = class(TCustomFidoVerify)
  public
    function VerifyAndSaveCred( credJson : string ) : string;
  end;

// ###########################################
// #### Assertion
type
  TFidoUserAssert = class(TCustomFidoVerify)
  private
    fRand : TRandomGenerator;
    fOwnsRandom : boolean;
    function CheckCredentials(userHandle: string; origChallenge: ISuperObject;
      var credId: string): boolean;
  public
    function StartAssertion( uname : string ) : string;
    function VerifyAssert( assertionStr : string; var resStr : string ) : boolean;

    constructor Create(rand : TRandomGenerator);
    destructor Destroy; override;
  end;

// ###########################################
// #### User registration handling
type
  IFidoDataHandling = interface
  ['{B3AF2050-BB60-46DC-8BBA-9102076F2480}']
    function IsAlreadRegistered( uname : string ) : boolean; overload;
    function IsAlreadRegistered( uname : string; var credIDFN : string ) : boolean; overload;

    function IsChallengeInitiated( challenge : string ) : boolean;

    procedure SaveUserInitChallenge( user : TFidoUserStartRegister );
    procedure SaveCred( challenge : string; cred : TFidoCredVerify; authData : TAuthData );

    function CredToUser(credId: string; var uname: string): boolean;
    procedure SaveAssertChallengeData( challenge : ISuperObject );
    function LoadAssertChallengeData( challenge : string ) : ISuperObject;
    function CheckSigCounter(credId: string; authData: TAuthData): boolean;
  end;


function FidoServer : TFidoServer;
function SHA256FromBuf( buf : PByte; len : integer ) : TFidoSHA256Hash;

procedure SetFidoDataHandler( aHandler : IFidoDataHandling );
function FidoDataHandler : IFidoDataHandling;

implementation

uses syncObjs, strUtils, Classes, IdHashSHA, IdGlobal, IdSSLOpenSSLHeaders,
     Fido2dll, Windows;

var locServer : TFidoServer = nil;
    locDataHandler : IFidoDataHandling = nil;
    cs : TCriticalSection;

procedure SetFidoDataHandler( aHandler : IFidoDataHandling );
begin
     locDataHandler := aHandler;
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

constructor TFidoUserStartRegister.Create(UName, displName: string; rand : TRandomGenerator);
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
         fChallenge[i] := fRand.RandInt( 256 );
end;

procedure TFidoUserStartRegister.InitUserId;
var i : integer;
begin
     // first byte of the random user ID shall not be one or zero
     // see: https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/User_Handle.html
     repeat
           fUserid[0] := fRand.RandInt( 256 );
     until fUserid[0] > 1;

     for i := 1 to High(fUserid) do
         fUserid[i] := fRand.RandInt( 256 );
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

function SHA256FromBuf( buf : PByte; len : integer ) : TFidoSHA256Hash;
var hash : TIdHashSHA256;
    indyBuf : TidBytes;
    res : TidBytes;
begin
     if not IdSSLOpenSSLHeaders.Load then
        raise Exception.Create('Failed to load Openssl lib');
     
     if not TIdHashSHA256.IsAvailable then
        raise Exception.Create('Hashing function not available');

     hash := TIdHashSHA256.Create;
     try
        SetLength(indyBuf, len);
        Move( buf^, indyBuf[0], len);

        res := hash.HashBytes(indyBuf);

        if length(res) <> sizeof(result) then
           raise Exception.Create('Hash failed');

        Move( res[0], Result[0], sizeof(Result));
     finally
            hash.Free;
     end;
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
     Result := false;

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

     // minimum requirements
     Result := (fmt <> '') and (alg <> 0);
end;


{ TFidoUserRegisterVerify }

function TFidoUserRegisterVerify.VerifyAndSaveCred(credJson: string): string;
var clientData : ISuperObject;
    s : string;
    credentialId : string;
    rawId : TBytes;
    credVerify : TFidoCredVerify;
    sig : TBytes;
    x5c : TBytes;
    authData : TBytes;
    fmt : string;
    alg : integer;
    res : boolean;
    credFMT : TFidoCredentialFmt;
    authDataObj : TAuthData;
    restBuf : TBytes;
    clientDataStr : RawByteString;
    clientDataHash : TFidoSHA256Hash;
    serverRPIDHash : TFidoSHA256Hash;
    rpIDHash : TFidoRPIDHash;
    credential : ISuperObject;
begin
     Result := '{"error":0,"msg":"Error parsing content"}';

     credential := SO(credJSON);
     if not Assigned(credential) then
        exit;

     s := credential.S['response.clientDataJSON'];

     if s = '' then
        exit;

     ClientData := So( String(Base64URLDecode( s )) );
     if clientData = nil then
        exit;

     // ###########################################
     // #### Check if the challenge has been initiated
     if not FidoDataHandler.IsChallengeInitiated(ClientData.S['challenge']) then
     begin
          Result := '{"error":1,"msg":"Client data json parsing error - challenge not initiated"}';

          exit;
     end;

     // calculate hash from clientDataJSON
     clientDataStr := Base64URLDecode( credential.S['response.clientDataJSON'] );
     if clientDataStr = '' then
     begin
          Result := '{"error":2,"msg":"Client data json missing"}';

          exit;
     end;

     // create the client hash that is later used in the verification process
     clientDataHash := SHA256FromBuf( @clientDataStr[1], Length(clientDataStr) );

     clientData := SO( String( clientDataStr ) );

     s := credential.S['response.attestationObject'];
     if s = '' then
        exit;

     if not DecodeAttestationObj(s, alg, fmt, sig, authData, x5c) then
     begin
          Result := '{"error":2,"msg":"Decoding failed"}';
          exit;
     end;

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

     authDataObj := nil;
     if Length(restBuf) > 0 then
        raise Exception.Create('Damend there is a rest buffer that should not be');

     if Length(authData) > 0 then
        authDataObj := TAuthData.Create( authData );
     try
        if not Assigned(authDataObj) then
           exit;

        if not authDataObj.UserPresent then
        begin
             Result := '{"error":3,"msg":"Error: parameter user present not set"}';
             exit;
        end;

        if authDataObj.UserVerified <> FidoServer.UserVerification then
        begin
             Result := '{"error":4,"msg":"Error: parameter user verification not set to the default"}';
             exit;
        end;

        // check rp hash
        rpIDHash := authDataObj.rpIDHash;
        serverRPIDHash := FidoServer.RPIDHash;
        if not CompareMem( @rpIDHash[0], @serverRPIDHash[0], sizeof(rpIDHash)) then
        begin
             Result := '{"error":4,"msg":"The relying party hash does not match"}';
             exit;
        end;

        if fmt = 'packed'
        then
            credFmt := fmFido2
        else if fmt = 'fido-u2f'
        then
            credFmt := fmU2F
        else
            credFmt := fmDef;

        // ###########################################
        // #### Now bring the fido dll into action
        credVerify := TFidoCredVerify.Create( TFidoCredentialType(alg), credFmt,
                                              FidoServer.RelyingPartyId, FidoServer.RelyingParty,
                                              TBaseFido2Credentials.WebAuthNObjDataToAuthData( authData ),
                                              x5c, sig,
                                              FidoServer.RequireResidentKey,
                                              authDataObj.UserVerified, 0)  ;
        try
           res := credVerify.Verify(clientDataHash);

           if res then
           begin
                // ###########################################
                // #### save EVERYTHING to a database
                FidoDataHandler.SaveCred(ClientData.S['challenge'], credVerify, authDataObj);
           end;
        finally
               credVerify.Free;
        end;
     finally
            authDataObj.Free;
     end;

     // build result and generate a session
     if res then
     begin
          // yeeeha we got it done
          Result := '{"success":true}';
     end
     else
         Result := '{"success":false}';
end;


{ TFidoUserAssert }

constructor TFidoUserAssert.Create(rand: TRandomGenerator);
begin
     fRand := rand;

     if not Assigned(fRand) then
        fRand := TRandomGenerator.Create(raOS);

     fOwnsRandom := rand <> fRand;

     inherited Create;
end;

destructor TFidoUserAssert.Destroy;
begin
     if fOwnsRandom then
        fRand.Free;

     inherited;
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

     res := SO('{"publicKey":{"allowCredentials":[]}}');

     for i := 0 to Length(challenge) - 1 do
         challenge[i] := fRand.RandInt( 256 );

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
     if userHandle <> ''
     then
         Result := FidoDataHandler.IsAlreadRegistered(userHandle, credId)
     else
     begin
          Result := False;
          cred := origChallenge.A['publicKey.allowCredentials'];
          if (cred <> nil) and (cred.Length > 0) then
          begin
               Result := True;
               credId := cred.O[0].S['id'];
          end;
     end;
end;


function TFidoUserAssert.VerifyAssert(assertionStr: string;
  var resStr: string): boolean;
var clientData : ISuperObject;
    userHandle : string;
    sig : TBytes;
    credID : string;
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
    uname : string;
    res : ISuperObject;
    assertion : ISuperObject;
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

     authDataObj := nil;
     if Length(authData) > 0 then
        authDataObj := TAuthData.Create( authData );
     try
        if not Assigned(authDataObj) then
           exit;

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
        buf := Base64URLDecodeToBytes( clientData.S['challenge']);

        if Length(buf) <> sizeof(challenge) then
        begin
             resStr := '{"error":5,"msg":"Challange type failed"}';
             exit;
        end;
        move( buf[0], challenge, sizeof(challenge));

        // ###########################################
        // #### Verify with the fido dll
        assertVerify := TFidoAssertVerify.Create;
        try
           assertVerify.RelyingParty := FidoServer.RelyingPartyId;
           assertVerify.LoadPKFromFile( credId + '.pk');
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
                res := SO('{"success":true}');
                res.S['username'] := uname;
                resStr := res.AsJSon;
                Result := True;
           end
           else
           begin
                resStr := '{"success":false}';
           end;
        finally
               assertVerify.Free;
        end;
     finally
            authDataObj.Free;
     end;
end;


initialization
  cs := TCriticalSection.Create;
finalization
  locServer.Free;
  cs.Free;

end.
