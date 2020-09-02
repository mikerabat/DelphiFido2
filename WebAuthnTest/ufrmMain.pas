unit ufrmMain;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, WebAuthn;

type
  TfrmWebAuthnTest = class(TForm)
    btnVersion: TButton;
    memLog: TMemo;
    btnUserVerifyAvail: TButton;
    btnCredential: TButton;
    btnCheckJSON: TButton;
    btnAssert: TButton;
    procedure btnVersionClick(Sender: TObject);
    procedure btnUserVerifyAvailClick(Sender: TObject);
    procedure btnCredentialClick(Sender: TObject);
    procedure btnCheckJSONClick(Sender: TObject);
    procedure btnAssertClick(Sender: TObject);
  private
    procedure WriteCredAttest(pCred : PWEBAUTHN_CREDENTIAL_ATTESTATION);
    procedure WriteAssertion( pAssert : PWEBAUTHN_ASSERTION; clientData : UTF8String );
    { Private-Deklarationen }
  public
    { Public-Deklarationen }
  end;

var
  frmWebAuthnTest: TfrmWebAuthnTest;

implementation

uses IdHashSha, cbor, AuthData, SuperObject;

{$R *.dfm}

// just one example. for testing fidotest.com can point to localhost via the hosts file ;)
const cClientData : UTF8String = '{' +
 '"hashAlgorithm": "SHA-256",' +
 '"challenge": "fzjg31IEKi6ZxKqsQ9S_XHG9WvdmcXPah5EXd11p1bU",' +
 '"origin": "https:\/\/fidotest.com",' +
 '"clientExtensions": {},' +
 '"type": "webauthn.create"' +
 '}';
 cRefHost = 'fidotest.com';


procedure TfrmWebAuthnTest.btnVersionClick(Sender: TObject);
begin
     memLog.Lines.Add('Web Auth Version: ' + IntToStr( WebAuthNGetApiVersionNumber ) );
end;

procedure TfrmWebAuthnTest.btnAssertClick(Sender: TObject);
var webauthJSON : ISuperObject;
    WebAuthNClientData : TWebAuthnClientData; // _In_
    WebAtuhNGetAssertionOption : TWebAuthNAuthenticatorGetAsserrtionOptions;
    hr : HRESULT;
    pWebAuthNAssertion : PWebAutNAssertion;
    credList : Array[0..0] of TWebAuthNCredential;
    credIDBuf : TBytes;
    cancellationID : TGuid;
    soClData : ISuperObject;
    challange : Array[0..63] of byte;
    i: Integer;
    clientData : UTF8String;
begin
     if not FileExists('webauth.json') then
        raise Exception.Create('Cannot find original credential file');

     with TStringLIst.Create do
     try
        LoadFromFile('webauth.json');
        webauthJSON := SO(Text);
     finally
            Free;
     end;

     // ################################################
     // #### Client data
     soClData := SO(String(cClientData));

     // create new challange
     for i := 0 to Length(challange) - 1 do
         challange[i] := random( 255 );

     soClData.S['challenge'] := Base64URLEncode(@challange[0], Length(challange) );
     clientData := UTF8String(soCLData.AsJSon);

     FillChar(WebAuthNClientData, sizeof(WebAuthNClientData), 0);
     WebAuthNClientData.dwVersion := WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
     WebAuthNClientData.cbClientDataJSON := Length(clientData);
     WebAuthNClientData.pbClientDataJSON := PAnsiChar(clientData);
     WebAuthNClientData.pwszHashAlgId := WEBAUTHN_HASH_ALGORITHM_SHA_256;

     // ###########################################
     // #### Prepare credential list
     credIDBuf := Base64URLDecodeToBytes(webauthJSON.S['id']);

     credList[0].dwVersion := WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
     credList[0].cbId := Length(credIDBuf);
     credList[0].pbId := @credIDBuf[0];
     credList[0].pwszCredentialType := WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

     // ###########################################
     // #### Fill in params
     assert( WebAuthNGetCancellationId(cancellationID) = S_OK, 'Cancellation ID failed');

     FillChar(WebAtuhNGetAssertionOption, sizeof(WebAtuhNGetAssertionOption), 0);
     WebAtuhNGetAssertionOption.dwVersion := WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;
     WebAtuhNGetAssertionOption.dwTimeoutMilliseconds := 20000;
     WebAtuhNGetAssertionOption.CredentialList.cCredentials := Length(credList);
     WebAtuhNGetAssertionOption.CredentialList.pCredentials := @credList;
     WebAtuhNGetAssertionOption.Extensions.cExtensions := 0;
     WebAtuhNGetAssertionOption.Extensions.pExtensions := nil;
     WebAtuhNGetAssertionOption.dwAuthenticatorAttachment := WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
     WebAtuhNGetAssertionOption.dwUserVerificationRequirement := WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED; //WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
     WebAtuhNGetAssertionOption.dwFlags := 0;
     WebAtuhNGetAssertionOption.pwszU2fAppId := nil;
     WebAtuhNGetAssertionOption.pbU2fAppId := nil;
     WebAtuhNGetAssertionOption.pCancellationId := nil;
     WebAtuhNGetAssertionOption.pCancellationId := @cancellationID;

     pWebAuthNAssertion := nil;
     hr := WebAuthNAuthenticatorGetAssertion( Handle,
                                              PChar(cRefHost),
                                              @WebAuthNClientData,
                                              @WebAtuhNGetAssertionOption,
                                              pWebAuthNAssertion );

     if hr = S_OK then
     begin
          ShowMessage( 'Successfully created assertion');
          memLog.Lines.Add('Created assertion -> now it would be time to validate on the host');
          WriteAssertion( pWebAuthNAssertion, clientData );

          WebAuthNFreeAssertion( pWebAuthNAssertion );
     end;
end;

procedure TfrmWebAuthnTest.btnCheckJSONClick(Sender: TObject);
var webauthJSON : ISuperObject;
    attest : TCborMap;
    authData : TAuthData;

begin
     with TStringLIst.Create do
     try
        LoadFromFile('webauth.json');
        webauthJSON := SO(Text);
     finally
            Free;
     end;

     attest := TCborDecoding.DecodeBase64Url(webauthJSON.S['response.attestationObject']) as TCborMap;
     try
        memLog.Lines.Add(attest.ToString);

        authData := TAuthData.Create((attest.ValueByName['authData'] as TCborByteString).ToBytes);

        memLog.Lines.Add('');
        memLog.Lines.Add('AuthData:' );
        if authData <> nil then
           memLog.Lines.Add(authData.ToString);
        authData.Free;
     finally
            attest.Free;
     end;
end;

procedure TfrmWebAuthnTest.WriteAssertion(pAssert: PWEBAUTHN_ASSERTION; clientData : UTF8String);
var jsonOut : ISuperObject;
begin
     jsonout := SO;

     jsonout.S['response.authenticatorData'] := Base64URLEncode( pAssert^.pbAuthenticatorData, pAssert^.cbAuthenticatorData );
     jsonout.S['resopnse.signature'] := Base64URLEncode( pAssert^.pbSignature, pAssert^.cbSignature );
     jsonout.S['response.userHandle'] := Base64URLEncode( pAssert^.pbUserId, pAssert^.cbUserId );
     jsonout.S['response.clientDataJSON'] := Base64URLEncode( @clientData[1], Length(clientData) );

     jsonout.S['id'] := Base64URLEncode( pAssert^.Credential.pbId, pAssert^.Credential.cbId );
     jsonout.S['rawId'] := Base64URLEncode( pAssert^.Credential.pbId, pAssert^.Credential.cbId );
     jsonout.S['type'] := pAssert^.Credential.pwszCredentialType;

     jsonout.SaveTo('webauthn_assert.json');

     memLog.Lines.Add('');
     memLog.Lines.Add('Assertion json: ' );
     memLog.Lines.Add(jsonout.AsJSon(True, True));

end;

procedure TfrmWebAuthnTest.WriteCredAttest(
  pCred: PWEBAUTHN_CREDENTIAL_ATTESTATION);
var jsonOut : ISuperObject;
begin
     jsonout := SO;
     jsonout.S['type'] := pCred^.pwszFormatType;
     jsonout.S['response.attestationObject'] := Base64URLEncode( pCred^.pbAttestationObject, pCred^.cbAttestationObject );
     jsonout.S['response.clientDataJSON'] := Base64URLEncode( @cClientData[1], Length(cClientData) );
     jsonout.S['id'] := Base64URLEncode( pCred^.pbCredentialId, pCred^.cbCredentialId );
     jsonout.S['rawid'] := Base64URLEncode( pCred^.pbCredentialId, pCred^.cbCredentialId );

     // additional fields not used e.g. on webauthn.io
     if (pCred^.dwUsedTransport and WEBAUTHN_CTAP_TRANSPORT_FLAGS_MASK) = WEBAUTHN_CTAP_TRANSPORT_USB then
        jsonout.s['transport'] := 'USB';
     if (pCred^.dwUsedTransport and WEBAUTHN_CTAP_TRANSPORT_FLAGS_MASK) = WEBAUTHN_CTAP_TRANSPORT_BLE then
        jsonout.s['transport'] := 'BLE';
     if (pCred^.dwUsedTransport and WEBAUTHN_CTAP_TRANSPORT_FLAGS_MASK) = WEBAUTHN_CTAP_TRANSPORT_TEST then
        jsonout.s['transport'] := 'Test';
     if (pCred^.dwUsedTransport and WEBAUTHN_CTAP_TRANSPORT_FLAGS_MASK) = WEBAUTHN_CTAP_TRANSPORT_INTERNAL then
        jsonout.s['transport'] := 'Internal';

     jsonout.S['debug.authData'] := Base64URLEncode( pCred^.pbAuthenticatorData, pCred^.cbAuthenticatorData );
     jsonout.S['debug.attestation'] := Base64URLEncode( pCred^.pbAttestation, pCred^.cbAttestation );

     jsonout.SaveTo('webauth.json');
end;

procedure TfrmWebAuthnTest.btnUserVerifyAvailClick(Sender: TObject);
var isAvail : BOOL;
    hr : HRESULT;
begin
     hr := WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable( isAvail );

     if hr = S_OK then
     begin
          memLog.Lines.Add('Verifying Platform Avail: ' + BoolToStr(isAvail, True ) );
     end
     else
         memLog.Lines.Add('Call Failed');
end;

procedure TfrmWebAuthnTest.btnCredentialClick(Sender: TObject);
var RpInformation : TWebAuthnRPEntityInformation; // _In_
    UserInformation : TWebAuthUserEntityInformation; // _In_
    PubKeyCredParams : TWebauthnCoseCredentialParameters; // _In_
    WebAuthNClientData : TWebAuthnClientData; // _In_
    WebAuthNMakeCredentialOptions : TWebAuthnAuthenticatorMakeCredentialOptions; // _In_opt_
    pWebAuthNCredentialAttestation : PWEBAUTHN_CREDENTIAL_ATTESTATION; // _Outptr_result_maybenull_
    hr : HRESULT;
    coseParams : Array[0..1] of WEBAUTHN_COSE_CREDENTIAL_PARAMETER;
    i : integer;
    uid : Array[0..31] of byte;
    cancellationID : TGuid;
    bufClientData : UTF8String;
begin
     // ################################################
     // #### relying party
     FillChar(RpInformation, sizeof(RpInformation), 0);
     RpInformation.dwVersion := WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
     RpInformation.pwszId := cRefHost;
     RpInformation.pwszName := 'Sweet home localhost';
     RpInformation.pwszIcon := nil;

     // ################################################
     // #### user information
     FillChar(UserInformation, sizeof(UserInformation), 0);
     UserInformation.dwVersion := WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
     UserInformation.cbId := sizeof( uid );

     Randomize;

     // create credentials
     for i := 0 to Length(uid) - 1 do
     begin
          uid[i] := Byte( Random(High(byte) + 1) );
     end;

     UserInformation.pbId := @uid[0];
     UserInformation.pwszName := 'test';
     UserInformation.pwszIcon := niL;
     UserInformation.pwszDisplayName := 'Test display name';

     // ################################################
     // #### Client data
     bufClientData := Copy( cClientData, 1, Length(cClientData));
     FillChar(WebAuthNClientData, sizeof(WebAuthNClientData), 0);
     WebAuthNClientData.dwVersion := WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
     WebAuthNClientData.cbClientDataJSON := Length(cClientData);
     WebAuthNClientData.pbClientDataJSON := PAnsiChar(bufClientData);
     WebAuthNClientData.pwszHashAlgId := WEBAUTHN_HASH_ALGORITHM_SHA_256;

     // ################################################
     // #### pub ked credential params
     PubKeyCredParams.cCredentialParameters := Length(coseParams);
     PubKeyCredParams.pCredentialParameters := @coseParams[0];

     coseParams[0].dwVersion := WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
     coseParams[0].pwszCredentialType := WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
     coseParams[0].lAlg := WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;

     coseParams[1].dwVersion := WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
     coseParams[1].pwszCredentialType := WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
     coseParams[1].lAlg := WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256;

     // ###########################################
     // #### Fill in params
     FillChar(WebAuthNMakeCredentialOptions, sizeof(WebAuthNMakeCredentialOptions), 0);
     WebAuthNMakeCredentialOptions.dwVersion := WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
     WebAuthNMakeCredentialOptions.dwTimeoutMilliseconds := 20000;
     WebAuthNMakeCredentialOptions.bRequireResidentKey := False;
     WebAuthNMakeCredentialOptions.dwAuthenticatorAttachment := WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
     WebAuthNMakeCredentialOptions.dwUserVerificationRequirement := WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
     WebAuthNMakeCredentialOptions.dwAttestationConveyancePreference := WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT;

     // ###########################################
     // #### Cancellation
     assert( WebAuthNGetCancellationId(cancellationID) = S_OK, 'Cancellation ID failed');
     WebAuthNMakeCredentialOptions.pCancellationId := @cancellationID;

     // ###########################################
     // #### do the magic
     pWebAuthNCredentialAttestation := nil;
     hr := WebAuthNAuthenticatorMakeCredential( Handle,
                                                @RpInformation,
                                                @UserInformation,
                                                @PubKeyCredParams,
                                                @WebAuthNClientData,
                                                @WebAuthNMakeCredentialOptions,
                                                pWebAuthNCredentialAttestation );

     if hr = S_OK then
     begin
          WriteCredAttest( pWebAuthNCredentialAttestation );

          WebAuthNFreeCredentialAttestation( pWebAuthNCredentialAttestation );
          memLog.Lines.Add('Finished');
     end
     else
     begin
          memLog.Lines.Add('Make Cred failed with: ' + WebAuthNGetErrorName( hr ));
     end;
end;

end.

