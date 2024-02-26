// ###################################################################
// #### This file is part of the mathematics library project, and is
// #### offered under the licence agreement described on
// #### http://www.mrsoft.org/
// ####
// #### Copyright:(c) 2020, Michael R. . All rights reserved.
// ####
// #### Unless required by applicable law or agreed to in writing, software
// #### distributed under the License is distributed on an "AS IS" BASIS,
// #### WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// #### See the License for the specific language governing permissions and
// #### limitations under the License.
// ###################################################################

unit authData;

interface

uses SysUtils, Types, cbor;

type
  TFidoRPIDHash = Array[0..31] of byte;
  EAuthDataException = class(Exception);

// ###########################################
// #### Decodes the Authenticator buffer for both the enrolling process and
// assertion process (with less data)
type
  TAuthData = class(TObject)
  private
    // minimum
    frpIDHash : TFidoRPIDHash;
    fflags : byte;                // bit 0: user present
                                  // bit 2: user verification
                                  // bit 6: attested credential data included
                                  // bit 7: extension included
    fsignCnt : LongWord;

    // attested credential data (optional)
    faaGUID : TGuid;
    fcredIDLend : word;
    fCredID : TBytes;
    fCred : TCborMap;

    fPubType : integer;
    fPubAlg : integer;
    fPublicKeyData1 : TBytes;    // field -1
    fPublicKeyData2 : TBytes;    // field -2
    fPublicKeyData3 : TBytes;    // field -3
    fHasPublicKey : boolean;

    fExtensions : TCborItem;
    fRawAuthData : TBytes;
  public
    function UserPresent : boolean;
    function UserVerified : boolean;
    function HasAttestedData : boolean;
    function HasExtensions : boolean;

    function RPIDHash : TFidoRPIDHash;
    function SigCount : LongWord;
    function AAUID : TGuid;

    function HasPublicKey : boolean;
    function KeyType : integer;
    function PublicKeyAlg : integer;
    function CredId : TBytes;

    function AttestData1 : TBytes;
    function AttestData2 : TBytes;
    function AttestData3 : TBytes;

    function ToString : string; override;

    function RawData : TBytes;

    constructor Create( fromData : TBytes ); overload;
    constructor Create( data : PByte; len : integer); overload;
    destructor Destroy; override;
  end;

implementation

uses SuperObject, Fido2dll;

{ TAuthData }

function TAuthData.UserPresent: boolean;
begin
     Result := (fflags and $01) <> 0;
end;

function TAuthData.UserVerified: boolean;
begin
     Result := (fflags and $04) <> 0;
end;

function TAuthData.HasAttestedData: boolean;
begin
     Result := (fflags and $40) <> 0;
end;

function TAuthData.HasExtensions: boolean;
begin
     Result := (fflags and $80) <> 0;
end;

function TAuthData.HasPublicKey: boolean;
begin
     Result := fHasPublicKey;
end;

function TAuthData.KeyType: integer;
begin
     Result := fPubType;
end;

function TAuthData.PublicKeyAlg: integer;
begin
     // only valid if HasPublicKey is valid
     if fHasPublicKey
     then
         Result := fPubAlg
     else
         Result := 0;
end;

function TAuthData.RawData: TBytes;
begin
     Result := fRawAuthData;
end;

function TAuthData.RPIDHash: TFidoRPIDHash;
begin
     Result := frpIDHash;
end;

function TAuthData.SigCount: LongWord;
begin
     Result := fsignCnt;
end;

procedure RevertByteOrder( stream : PByte; numBytes : integer);
var i: Integer;
    pEnd : PByte;
    tmp : byte;
begin
     pEnd := stream;
     inc(pEnd, numBytes - 1);
     for i := 0 to numBytes div 2 - 1 do
     begin
          tmp := stream^;
          stream^ := pEnd^;
          pEnd^ := tmp;
          inc(stream);
          dec(pEnd);
     end;
end;


constructor TAuthData.Create(fromData: TBytes);
var idx : integer;
    numDecoded : integer;
    coseIdx1, coseIdx2, coseIdx3, coseIdx4, coseIdx5 : integer;
    cose1 : TCborUINTItem;
    cose2 : TCborNegIntItem;
begin
     fRawAuthData := Copy(fromData, 0, Length(fromData));

     // according to https://www.w3.org/TR/webauthn/#sctn-attestation
     // the attestation object subtype authData is:
     // 32 bytes of rpIDHash
     // 1 byte flags:
     // 4 bytess counter. -> a total of 37 bytes minimum
     // if AttestedData flag is set then
     // 16 bytes AAUID of the key
     // 2 bytes Credential id length
     // followed this number of bytes credential id
     // followed by the credential public key (variable length COSE_key)
     //    this data is cbor encoded
     // if extended flag is set the rest is
     // a cbor map of extended flags

     cose1 := nil;
     fHasPublicKey := False;

     if Length(fromData) < 37 then
        raise EAuthDataException.Create('Error at least 37 bytes required');

     Move( fromData[0], frpIDHash, sizeof(frpIDHash));
     fflags := fromData[32];
     fsignCnt := PLongWord( @fromData[33] )^;
     RevertByteOrder( @fsignCnt, sizeof(fsignCnt));

     fPubType := -1;
     idx := 37;
     if HasAttestedData then
     begin
          if Length(fromData) < idx + sizeof(word) + sizeof(TGuid) then
             raise EAuthDataException.Create('Error no memory for attestation data');

          Move( fromData[idx], faaGUID, sizeof(faaGUID));

          idx := idx + sizeof(TGUID);
          fcredIDLend := PWord(@fromData[idx])^;
          RevertByteOrder(@fcredIDLend, sizeof(fcredIDLend));
          inc(idx, sizeof(word));
          if Length(fromData) < idx + fcredIDLend then
             raise EAuthDataException.Create('Bad attestation data - data too short');

          SetLength(fCredID, fcredIDLend);
          if fcredIDLend > 0 then
             Move(fromData[idx], fCredID[0], fcredIDLend);

          inc(idx, fcredIDLend);

          numDecoded := 0;
          if idx < Length(fromData) then
          begin
               // decode credential public key...
               fCred := TCborDecoding.DecodeData(@fromData[idx], Length(fromData) - idx, numDecoded) as TCborMap;

               // for now we just check if fields 1, 3, -2 and -3 are available and the
               // key type is in in the range of the ones supported from the fido dll
               coseIdx1 := fCred.IndexOfName('1');
               coseIdx2 := fCred.IndexOfName('3');
               coseIdx3 := fCred.IndexOfName('-1');
               coseIdx4 := fCred.IndexOfName('-2');
               coseIdx5 := fCred.IndexOfName('-3');


               if (coseIdx1 < 0) or (coseIdx2 < 0) or (coseIdx3 < 0) then
                  raise EAuthDataException.Create('Credential public key does not contain the fields "1", "3" or "-1"');

               cose1 := fCred.Values[coseIdx1] as TCborUINTItem;

               // COSE_KTY_OKP	= 1;
               // COSE_KTY_EC2	= 2;
               // COSE_KTY_RSA	= 3;
               if not (cose1.Value in [COSE_KTY_OKP, COSE_KTY_EC2, COSE_KTY_RSA]) then
                  raise EAuthDataException.Create('Cose type not in the expected range');
               fPubType := Integer(cose1.Value);

               // COSE_ES256	= -7;
               // COSE_EDDSA	= -8;
               // COSE_RS256	= -257;
               cose2 := fCred.Values[coseIdx2] as TCborNegIntItem;
               if (cose2.Value <> COSE_ES256) and (cose2.Value <> COSE_EDDSA) and (cose2.Value <> COSE_RS256) then
                  raise EAuthDataException.Create('Cose algorithm not recognized');

               fPubAlg := cose2.Value;

               // COSE_KTY_EC2: -1: p-256 curve, -2: x coordinate as byte string, -3: y - coordinate as byte string
               // COSE_RS256: -1: rsa modulos, -2 rsa public exponent
               if coseIdx3 >= 0 then
               begin
                    if fCred.Values[coseIdx3] is TCborByteString
                    then
                        fPUblicKeyData1 := (fCred.Values[coseIdx3] as TCborByteString).ToBytes
                    else if fCred.Values[coseIdx3] is TCborUINTItem then
                    begin
                         SetLength(fPUblicKeyData1, sizeof(Uint64));
                         Move( (fCred.Values[coseIdx3] as TCborUIntItem).Value, fPUblicKeyData1[0], sizeof(UINt64));
                    end;
               end;

               if coseIdx4 >= 0 then
                  fPUblicKeyData2 := (fCred.Values[coseIdx4] as TCborByteString).ToBytes;
               if coseIdx5 >= 0 then
                  fPUblicKeyData3 := (fCred.Values[coseIdx5] as TCborByteString).ToBytes;
          end;

          idx := idx + numDecoded;
     end;

     if Assigned(cose1) then
     begin
          // todo: verify if that is correct - check the length...
          case cose1.Value of
            COSE_KTY_OKP: fHasPublicKey := (fPublicKeyData1 <> nil) and (fPublicKeyData2 <> nil);
            COSE_KTY_EC2: fHasPublicKey := (fPublicKeyData1 <> nil) and (fPublicKeyData2 <> nil) and (fPublicKeyData3 <> nil);
            COSE_KTY_RSA: fHasPublicKey := (fPublicKeyData1 <> nil) and (fPublicKeyData2 <> nil);
          else
              fHasPublicKey := False;
          end;
     end;

     if HasExtensions then
     begin
          // cbor encoded extensions
          fExtensions := TCborDecoding.DecodeData( @fromData[idx], Length(fromData) - idx);
     end;
end;

function TAuthData.AAUID: TGuid;
begin
     Result := faaGUID;
end;

function TAuthData.AttestData1: TBytes;
begin
     Result := fPublicKeyData1;
end;

function TAuthData.AttestData2: TBytes;
begin
     Result := fPublicKeyData2;
end;

function TAuthData.AttestData3: TBytes;
begin
     Result := fPublicKeyData3;
end;

constructor TAuthData.Create(data: PByte; len: integer);
var fromData : TBytes;
begin
     SetLength(fromData, len);
     if len > 0 then
        Move( data^, fromData[0], len);

     Create( fromData );
end;

function TAuthData.CredId: TBytes;
begin
     Result := fCredID;
end;

destructor TAuthData.Destroy;
begin
     fExtensions.Free;
     fCred.Free;

     inherited;
end;

function TAuthData.ToString: string;
var res : ISuperObject;
begin
     res := SO;
     res.S['aauid'] := GUIDToString( faaGUID );
     res.B['UserPresent'] := UserPresent;
     res.B['UserVerified'] := UserVerified;
     res.I['sigCnt'] := fsignCnt;
     res.S['hash'] := Base64URLEncode( @frpIDHash[0], Length(frpIDHash) );
     if Assigned(fCred) then
        res.S['cred'] := fCred.ToString;

     Result := res.AsJSon;
end;

end.
