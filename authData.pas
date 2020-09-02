unit authData;

interface

uses SysUtils, Types, cbor;

type
  TFidoRPIDHash = Array[0..31] of byte;
  EAuthDataException = class(Exception);

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

    fExtensions : TCborItem;
  public
    function UserPresent : boolean;
    function UserVerified : boolean;
    function HasAttestedData : boolean;
    function HasExtensions : boolean;

    function ToString : string; override;

    constructor Create( fromData : TBytes );
    destructor Destroy; override;
  end;

implementation

uses SuperObject;

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
    coseIdx1, coseIdx2, coseIdx3 : integer;
    cose1 : TCborUINTItem;
    cose2 : TCborNegIntItem;
begin
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

     if Length(fromData) < 37 then
        raise EAuthDataException.Create('Error at least 37 bytes required');

     Move( fromData[0], frpIDHash, sizeof(frpIDHash));
     fflags := fromData[32];
     fsignCnt := PLongWord( @fromData[33] )^;
     RevertByteOrder( @fsignCnt, sizeof(fsignCnt));

     idx := 37;
     if HasAttestedData then
     begin
          if Length(fromData) < idx + sizeof(word) + sizeof(TGuid) then
             raise EAuthDataException.Create('Error no memory for attestation data');

          Move( fromData[idx], faaGUID, sizeof(faaGUID));
          // todo: necessary to revert byte order?
          RevertByteOrder( @faaguid.D1, sizeof(faaGUID.D1));
          RevertByteOrder( @faaguid.D2, sizeof(faaGUID.D2));
          RevertByteOrder( @faaguid.D3, sizeof(faaGUID.D3));

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
               fCred := TCborDecoding.DecodeData(@fromData[idx], Length(fromData) - idx, numDecoded) as TCborMap;

               // for now we just check if fields 1, 3, -2 and -3 are available and the
               // key type is in in the range of the ones supported from the fido dll
               coseIdx1 := fCred.IndexOfName('1');
               coseIdx2 := fCred.IndexOfName('3');
               coseIdx3 := fCred.IndexOfName('-1');

               if (coseIdx1 < 0) or (coseIdx2 < 0) or (coseIdx3 < 0) then
                  raise EAuthDataException.Create('Credential public key does not contain the fields "1", "3" or "-1"');


               cose1 := fCred.Values[coseIdx1] as TCborUINTItem;

               // COSE_KTY_OKP	= 1;
               // COSE_KTY_EC2	= 2;
               // COSE_KTY_RSA	= 3;
               if not (cose1.Value in [1, 2, 3]) then
                  raise EAuthDataException.Create('Cose type not in the expected range');

               // COSE_ES256	= -7;
               // COSE_EDDSA	= -8;
               // COSE_RS256	= -257;
               cose2 := fCred.Values[coseIdx2] as TCborNegIntItem;
               if (cose2.Value <> -7) and (cose2.Value <> -8) and (cose2.Value <> -257) then
                  raise EAuthDataException.Create('Cose algorithm not recognized');
          end;

          idx := idx + numDecoded;
     end;

     if HasExtensions then
     begin
          // cbor encoded extensions
          fExtensions := TCborDecoding.DecodeData( @fromData[idx], Length(fromData) - idx);
     end;
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
