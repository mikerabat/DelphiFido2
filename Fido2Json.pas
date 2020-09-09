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

unit Fido2Json;

interface

uses SysUtils, Fido2, SuperObject, cbor;

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
  public
    property UserName : string read fUserName write fUserName;
    property UserDisplName : string read fDisplName write fDisplName;

    property UserId : TFidoUserId read fUserId write fUserId;
    property Challenge : TFidoChallenge read fChallenge write fChallenge;

    function ToJson : ISuperObject;

    constructor Create( UName, displName : string);
  end;

function FidoServer : TFidoServer;

function SHA256FromBuf( buf : PByte; len : integer ) : TFidoSHA256Hash;

implementation

uses syncObjs, strUtils, Classes, IdHashSHA, IdGlobal, IdSSLOpenSSLHeaders;

var locServer : TFidoServer = nil;
    cs : TCriticalSection;

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

constructor TFidoUserStartRegister.Create(UName, displName: string);
begin
     fDisplName := displName;
     fUserName := UName;

     if fDisplName = '' then
        fDisplName := fUserName;

     inherited Create;
end;

function TFidoUserStartRegister.ToJson: ISuperObject;
var server : ISuperObject;
begin
     // check if the user id and challenge is initialized
     if CompareMem( @fUserid[0], @cNoUserId[0], sizeof(fUserid)) then
        raise EFidoPropertyException.Create('No User ID created');
     if CompareMem(@fChallenge[0], @cNoChallange[0], sizeof(fChallenge)) then
        raise EFidoPropertyException.Create('No challenge created');

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

initialization
  cs := TCriticalSection.Create;
finalization
  locServer.Free;
  cs.Free;

end.
