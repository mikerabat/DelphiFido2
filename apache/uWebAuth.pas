unit uWebAuth;

interface

uses
  SysUtils, Classes, HTTPApp, RandomEng, superobject, Fido2Json, Fido2;

type
  TResponseHeaderType = (rtJSON, rtPNG, rtHTML, rtPDF, rtCSV, rtXML, rtBinary, rtZip, rtExe);

type
  TmodWebAuth = class(TWebModule)
    procedure WebModuleCreate(Sender: TObject);
    procedure modWebAuthitEnrollAction(Sender: TObject; Request: TWebRequest;
      Response: TWebResponse; var Handled: Boolean);
    procedure WebModuleDestroy(Sender: TObject);
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
    fRand : TRandomGenerator;

    function Base64Fixup( base64Str : string ): string;
    function IsAlreadRegistered( uname : string ) : boolean; overload;
    function IsAlreadRegistered( uname : string; var credIDFN : string ) : boolean; overload;

    function DecodeAttestationObj( attestStr : string; var alg : integer;
                                   var fmt : string; var sig, authData, x5c : TBytes ) : boolean;
    function VerifyCred( credential : ISuperObject ) : string;
    procedure SaveCred( userFn : string; cred : TFidoCredVerify );

    function StartAssert( userName : string ) : string;
    function VerifyAssert( assertion : ISuperObject ) : string;

    procedure prepareResponse(Response: TWebResponse;
      const rt: TResponseHeaderType = rtJSon);
    function getStringParam(Request : TWebRequest; const Name,
      defVal: string): string;
    { Private-Deklarationen }
  public
    { Public-Deklarationen }
  end;



var modWebAuth: TmodWebAuth;

implementation

uses Fido2Dll, cbor, authData, Windows;

{$R *.dfm}

procedure TmodWebAuth.prepareResponse(Response: TWebResponse; const rt: TResponseHeaderType = rtJSon);
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


procedure TmodWebAuth.SaveCred(userFn: string; cred: TFidoCredVerify);
var clientData : ISuperObject;
    credData : ISuperObject;
    credFN : string;
    credIDBase64 : string;
    credID : TBytes;
begin
     // load username
     with TStringList.Create do
     try
        LoadFromFile( userFn, TEncoding.ASCII );
        clientData := SO( Text );
     finally
            Free;
     end;

     credID := cred.CredID;
     credIDBase64 := Base64URLEncode( @credID[0], Length(credID) );

     credFN := credIDBase64 + '.json';
     credData := SO;
     credData.S['cert.pk'] := credIDBase64 + '.pk';
     credData.S['cert.sig'] := credIDBase64 + '.sig';
     credData.S['cert.x5c'] := credIDBase64 + '.x5c';

     cred.SavePKToFile(credIDBase64 + '.pk');
     cred.SaveSigToFile(credIDBase64 + '.sig');
     cred.SaveX5cToFile(credIDBase64 + '.x5c');

     credData.O['user'] := clientData.O['publicKey.user'].Clone;

     // link the credential to the username...
     with TStringList.Create do
     try
        if FileExists('users.txt') then
           LoadFromFile( 'users.txt' );
        Add(clientData.S['publicKey.user.name'] + '=' + credFN);

        // -> add the user handle to the file

        SaveToFile( 'users.txt' );
     finally
            Free;
     end;
end;

function TmodWebAuth.StartAssert(userName: string): string;
var res : ISuperObject;
    challenge : TFidoChallenge;
    i: Integer;
    credIDFN : string;
    credObj : ISuperObject;
begin
     credIDFN := '';
     if not IsAlreadRegistered(userName, credIDFN) then
        exit('{"error":0,"msg":"User not registered"}');

     res := SO('{"publicKey":{"allowCredentials":[]}}');

     for i := 0 to Length(challenge) - 1 do
         challenge[i] := fRand.RandInt( 256 );

     res.S['publicKey.challenge'] := Base64URLEncode(@challenge[0], length(challenge));
     res.I['publicKey.timeout'] := FidoServer.TimeOut;
     res.S['publicKey.rpid'] := FidoServer.RelyingPartyId;
     res.B['publicKey.userVerificaiton'] := FidoServer.UserVerification;


     credObj := SO( '{"type":"public-key"}' );
     credObj.S['id'] := Copy( credIDFN, 1, Length(credIDFN) - 5);

     res.A['publicKey.allowCredentials'].Add( credObj );

     res.O['extensions'] := SO('{"txAuthSimple":""}');

     Result := res.AsJSon;
end;

procedure TmodWebAuth.WebModuleCreate(Sender: TObject);
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
     fRand := TRandomGenerator.Create(raMersenneTwister);
     fRand.Init(0);
end;

function TmodWebAuth.DecodeAttestationObj(attestStr: string; var alg: integer;
  var fmt: string; var sig, authData, x5c: TBytes): boolean;
var cborItem : TCborMap;
    restBuf : TBytes;
    aName : string;
    attStmt : TCborMap;
    i, j : integer;
begin
     Result := false;

     // attestation object is a cbor encoded raw base64url encoded string
     cborItem := TCborDecoding.DecodeBase64UrlEx(attestStr, restBuf) as TCborMap;

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
             assert( cborItem.Names[i] is TCborUtf8String, 'CBOR type error');

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

     // minimum requirement
     Result := (fmt <> '') and (alg <> 0);
end;

function TmodWebAuth.getStringParam(Request : TWebRequest;
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


function TmodWebAuth.IsAlreadRegistered(uname: string;
  var credIDFN: string): boolean;
var idx : integer;
begin
     with TStringList.Create do
     try
        if FileExists('users.txt') then
        begin
             LoadFromFile( 'users.txt' );
        end;

        idx := IndexOfName( uname );
        Result := idx  >= 0;

        if Result then
           credIDFN := ValueFromIndex[idx];
     finally
            Free;
     end;
end;

procedure TmodWebAuth.modWebAuthitEnrollAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var uName, displName : string;
    user : TFidoUserStartRegister;
    challenge : TFidoChallenge;
    uid : TFidoUserId;
    i : integer;
    fn : String;
    obj : ISuperObject;
    s : UTF8String;
    challangeFN : string;
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

     // check if alread register
     if IsAlreadRegistered( uname ) then
     begin
          Response.Content := '{"result":2,"msg":"User already registered"}';
          exit;
     end;


     // now perpare a good response
     user := TFidoUserStartRegister.Create( uName, displName );
     try
        // init userid and challenge
        fn := '';
        for i := 0 to High(Challenge) do
            challenge[i] := fRand.RandInt( 256 );
        for i := 0 to High(uid) do
            uid[i] := fRand.RandInt( 256 );

        // create unique random uid and challange
        user.UserId := uid;
        user.Challenge := challenge;

        obj := user.ToJson;

        s := UTF8String( obj.AsJSon );

        // save to local file -> todo store in db
        challangeFN := obj.S['publicKey.challenge'];
        challangeFN := Base64Fixup( challangeFN ) + '.json';
        with TFileStream.Create( challangeFN, fmCreate) do
        try
           WriteBuffer( s[1], length(s));
        finally
               Free;
        end;

        Response.Content := obj.AsJSon;
     finally
            user.Free;
     end;
end;

procedure TmodWebAuth.WebModuleDestroy(Sender: TObject);
begin
     fRand.Free;
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


function TmodWebAuth.VerifyAssert(assertion: ISuperObject): string;
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
begin
     Result := '{"error":0,"msg":"Error parsing content"}';

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

     // create the client hash that is later used in the verification process
     clientDataHash := SHA256FromBuf( @clientDataStr[1], Length(clientDataStr) );

     authData := Base64URLDecodeToBytes(assertion.S['response.authenticatorData']);

     // check if anyhing is in place
     //if not (( alg = COSE_ES256 ) or (alg = COSE_EDDSA) or (alg = COSE_RS256)) then
     //   raise Exception.Create('Unknown algorithm');
     if Length(sig) = 0 then
        raise Exception.Create('No sig field provided');
     if Length(authData) = 0 then
        raise Exception.Create('Missing authdata');

     authDataObj := nil;
     if Length(authData) > 0 then
        authDataObj := TAuthData.Create( authData );
     try
        if not Assigned(authDataObj) then
           exit;

        OutputDebugString( PChar('Guid: ' + GuidToString(authDataObj.AAUID)) );

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

        // check signal counter
        //if authDAtaObj.SigCount < lastCounter then
//        begin
//             Result := '{"error":5,"msg":"Signal counter is too low - maybe cloned?"}';
//             exit;
//        end;

        // check rp hash
        rpIDHash := authDataObj.rpIDHash;
        serverRPIDHash := FidoServer.RPIDHash;
        if not CompareMem( @rpIDHash[0], @serverRPIDHash[0], sizeof(rpIDHash)) then
        begin
             Result := '{"error":6,"msg":"The relying party hash does not match"}';
             exit;
        end;

        credFmt := fmFido2;
        buf := Base64URLDecodeToBytes( clientData.S['challenge']);

        if Length(buf) <> sizeof(challenge) then
        begin
             Result := '{"error":5,"msg":"Challange type failed"}';
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
                Result := '{"success":true}';
           end
           else
           begin
                Result := '{"success":false}';
           end;
        finally
               Free;
        end;
     finally
            authDataObj.Free;
     end;
end;

function TmodWebAuth.VerifyCred( credential : ISuperObject ) : string;
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
    userDataFn : string;
    restBuf : TBytes;
    clientDataStr : RawByteString;
    clientDataHash : TFidoSHA256Hash;
    serverRPIDHash : TFidoSHA256Hash;
    rpIDHash : TFidoRPIDHash;
begin
     Result := '{"error":0,"msg":"Error parsing content"}';

     s := credential.S['response.clientDataJSON'];

     if s = '' then
        exit;

     ClientData := So( String(Base64URLDecode( s )) );
     if clientData = nil then
        exit;

     userDataFn := Base64Fixup( ClientData.S['challenge'] ) + '.json';

     // check if the challenge was requested here -> we can associate it with the user now ;)
     if not FileExists( userDataFn ) then
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
                SaveCred(userDataFn, credVerify);
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

procedure TmodWebAuth.modWebAuthwaAssertAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var assertion : ISuperObject;
begin
     prepareResponse(Response);

     assertion := SO( Request.Content );

     Response.Content := VerifyAssert( assertion );
end;

procedure TmodWebAuth.modWebAuthwaAssertStartAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
begin
     prepareResponse(Response);

     Response.Content := StartAssert( getStringParam(Request, 'uname', '') );
end;

procedure TmodWebAuth.modWebAuthwaEnrollVerifyAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
var credential : ISuperObject;

begin
     prepareResponse(Response);

     credential := SO(  Request.Content );

     Response.Content := VerifyCred(credential);
end;

procedure TmodWebAuth.modWebAuthwaSettingsAction(Sender: TObject;
  Request: TWebRequest; Response: TWebResponse; var Handled: Boolean);
begin
     prepareResponse(Response);

     Response.Content := FidoServer.ToJSON.AsJSon;
end;

procedure TmodWebAuth.modWebAuthwaUserExistsAction(Sender: TObject;
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

     if IsAlreadRegistered(uname)
     then
         response.Content := '{"result":2,"msg":"User already exists"}'
     else
         Response.Content := '{"result":0,"msg":"User does not exist"}';
end;

function TmodWebAuth.IsAlreadRegistered(uname: string): boolean;
var dummy : string;
begin
     Result := IsAlreadRegistered(uname, dummy);
end;

function TmodWebAuth.Base64Fixup(base64Str: string): string;
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

procedure fidoLogHandler(msg : PAnsiChar); cdecl;
begin
     OutputDebugStringA( msg );
end;

initialization
  fido_init(cFidoInitDebug);
  fido_set_log_handler(fidoLogHandler);

end.
