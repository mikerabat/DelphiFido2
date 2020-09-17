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

unit ufrmMain;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls;

const cChallangeSize = 32;

type
  TfrmFido2 = class(TForm)
    btnCheckKey: TButton;
    memLog: TMemo;
    lblHint: TLabel;
    btnWebAuthVersion: TButton;
    btnInfo: TButton;
    btnCreateCred: TButton;
    btnSetPin: TButton;
    lblUser: TLabel;
    edUsername: TEdit;
    lblDisplayname: TLabel;
    edDisplayName: TEdit;
    btnMakeAssert: TButton;
    btnReset: TButton;
    btnCredman: TButton;
    btnCreadCredObj: TButton;
    Button2: TButton;
    btnAssertObj: TButton;
    procedure FormCreate(Sender: TObject);
    procedure btnCheckKeyClick(Sender: TObject);
    procedure btnWebAuthVersionClick(Sender: TObject);
    procedure btnInfoClick(Sender: TObject);
    procedure btnCreateCredClick(Sender: TObject);
    procedure btnSetPinClick(Sender: TObject);
    procedure btnMakeAssertClick(Sender: TObject);
    procedure btnResetClick(Sender: TObject);
    procedure btnCredmanClick(Sender: TObject);
    procedure btnCreadCredObjClick(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure btnAssertObjClick(Sender: TObject);
  private
    { Private-Deklarationen }
    fWriteData : boolean;
    fUserPresence : boolean;
    fUserVerification : boolean;
    fUSBPath : AnsiString;
    fuserId : Array[0..cChallangeSize-1] of byte;
    fcdh : Array[0..cChallangeSize-1] of byte;
    procedure VerifyCredentials( typ : integer; fmt : PAnsiChar;
              authdataPtr : PByte; authDataLen : integer;
              x509Ptr : PByte; x509Len : integer;
              sigPtr : PByte; sigLen : integer;
              rk : boolean; uv : boolean; ext : integer);

    procedure VerifyAssert(typ : integer; authdata_ptr : PByte; authdata_len : integer;
                           sig_ptr : PByte; sig_len : integer;
                           ext : integer);
    procedure onFidoDLLLog(msg : string);
  public
    { Public-Deklarationen }
  end;

var
  frmFido2: TfrmFido2;

implementation

uses Fido2dll, webauthn, StrUtils, Fido2, authData, cbor;

{$R *.dfm}

procedure TfrmFido2.btnCheckKeyClick(Sender: TObject);
var devList : Pfido_dev_info_t;
    numFound : integer;
    retVal : integer;
    pMsg : PAnsiChar;
    i : integer;
    di : Pfido_dev_info_t;
const cNumMaxDev : integer = 64;
begin
     devList := fido_dev_info_new( cNumMaxDev );
     if devList = nil then
        raise Exception.Create('No list allocated');

     try
        numFound := 0;
        retVal := fido_dev_info_manifest( devList, cNumMaxDev, numFound );
        if retVal <> FIDO_OK then
        begin
             memLog.Lines.Add('Error found: ' + IntToStr(retVal));
             pMsg := fido_strerr( retVal );

             memLog.Lines.Add('Err Msg: ' + String(pMsg));
             exit;
        end;

        memLog.Lines.Add('Num found: ' + IntToStr(numFound));
        for i := 0 to numFound - 1 do
        begin
             di := fido_dev_info_ptr(devList, i);

             memLog.Lines.Add(Format(' %s: vendor=%d, product=%d, (%s, %s)', [
                     String( fido_dev_info_path(di) ), fido_dev_info_vendor( di ),
                     fido_dev_info_product(di),
                     String( fido_dev_info_manufacturer_string(di) ),
                     fido_dev_info_product_string(di)
                   ])
             );

             fUSBPath := AnsiString(fido_dev_info_path(di));
        end;
     finally
            fido_dev_info_free( @devList, cNumMaxDev );
     end;
end;

procedure TfrmFido2.FormCreate(Sender: TObject);
begin
     fUserPresence := True;
     fUserVerification := True;
     fido_init(cFidoInitDebug);

     InitFidoLogger( onFidoDLLLog );
end;

procedure TfrmFido2.onFidoDLLLog(msg: string);
begin
     memLog.Lines.Add('FidoDll: ' + msg);
end;

procedure TfrmFido2.VerifyCredentials(typ: integer; fmt: PAnsiChar;
  authdataPtr: PByte; authDataLen: integer; x509Ptr: PByte; x509Len: integer;
  sigPtr: PByte; sigLen: integer; rk, uv: boolean; ext: integer );
var cred : Pfido_cred_t;
    r : integer;
    //challange : Array[0..cChallangeSize - 1] of Byte;
begin
     //for i := 0 to cChallangeSize - 1 do
//         challange[i] := Byte( Random(High(byte) + 1) );

     cred := fido_cred_new;
     if cred = nil then
     begin
          memLog.Lines.Add('Failed to create credentials object');
          exit;
     end;
     try
        // type
        fido_cred_set_type( cred, typ );

        // client data hash
        r := fido_cred_set_clientdata_hash( cred, @fcdh[0], sizeof(fcdh));
        if r <> FIDO_OK then
        begin
             memLog.Lines.Add( Format('Failed: fido_cred_set_clientdata_hash: %s (%d)', [String(fido_strerr(r)), r]));
             exit;
        end;

        // relying party
        r := fido_cred_set_rp(cred, 'localhost', 'sweet home localhost');
        if r <> FIDO_OK then
        begin
             memLog.Lines.Add( Format('Failed: fido_cred_set_rp: %s (%d)', [String(fido_strerr(r)), r]));
             exit;
        end;

        // authdata
        r := fido_cred_set_authdata( cred, authdataPtr, authDataLen );
        if r <> FIDO_OK then
        begin
             memLog.Lines.Add( Format('Failed: fido_cred_set_authdata: %s (%d)', [String(fido_strerr(r)), r]));
             exit;
        end;

        // set extension
        r := fido_cred_set_extensions( cred, ext );
        if r <> FIDO_OK then
        begin
             memLog.Lines.Add( Format('Failed: fido_cred_set_extensions: %s (%d)', [String(fido_strerr(r)), r]));
             exit;
        end;

        // resident key
        if rk then
        begin
             r := fido_cred_set_rk( cred, FIDO_OPT_TRUE );
             if r <> FIDO_OK then
             begin
                  memLog.Lines.Add( Format('Failed: fido_cred_set_rk: %s (%d)', [String(fido_strerr(r)), r]));
                  exit;
             end;
        end;

        // user verification
        if uv then
        begin
             fido_cred_set_uv( cred, FIDO_OPT_TRUE);
             if r <> FIDO_OK then
             begin
                  memLog.Lines.Add( Format('Failed: fido_cred_set_uv: %s (%d)', [String(fido_strerr(r)), r]));
                  exit;
             end;
        end;

        r := fido_cred_set_x509( cred, x509Ptr, x509Len );
        if r <> FIDO_OK then
        begin
             memLog.Lines.Add( Format('Failed: fido_cred_set_x509: %s (%d)', [String(fido_strerr(r)), r]));
             exit;
        end;

        r := fido_cred_set_sig( cred, sigPtr, sigLen );
        if r <> FIDO_OK then
        begin
             memLog.Lines.Add( Format('Failed: fido_cred_set_sig: %s (%d)', [String(fido_strerr(r)), r]));
             exit;
        end;

        r := fido_cred_set_fmt( cred, fmt );
        if r <> FIDO_OK then
        begin
             memLog.Lines.Add( Format('Failed: fido_cred_set_fmt: %s (%d)', [String(fido_strerr(r)), r]));
             exit;
        end;

        // ###########################################
        // #### Verification
        r := fido_cred_verify( cred );
        if r <> FIDO_OK then
        begin
             memLog.Lines.Add( Format('Failed: fido_cred_verify: %s (%d)', [String(fido_strerr(r)), r]));
             exit;
        end;


        // ###########################################
        // #### Write blobs
        if fWriteData then
        begin
             if fido_cred_pubkey_len( cred ) > 0 then
             begin
                  with TFileStream.Create(edUsername.Text + '_pk.bin', fmCreate or fmOpenWrite) do
                  try
                     WriteBuffer( fido_cred_pubkey_ptr( cred)^, fido_cred_pubkey_len( cred ) );
                  finally
                         Free;
                  end;
             end;
             if fido_cred_id_len( cred ) > 0 then
             begin
                  with TFileStream.Create(edUsername.Text + '_id.bin', fmCreate or fmOpenWrite) do
                  try
                     WriteBuffer( fido_cred_id_ptr( cred)^, fido_cred_id_len( cred ) );
                  finally
                         Free;
                  end;
             end;
             with TFileStream.Create(edUsername.Text + '_uid.bin', fmCreate or fmOpenWrite) do
             try
                WriteBuffer( fuserId, sizeof(fUserId));
             finally
                    Free;
             end;

             with TFileStream.Create(edUsername.Text + '_chd.bin', fmCreate or fmOpenWrite) do
             try
                WriteBuffer( fcdh, sizeof(fcdh));
             finally
                    Free;
             end;

             if fido_cred_authdata_len( cred ) > 0 then
             begin
                  with TFileStream.Create(edUsername.Text + '_authdata.bin', fmCreate or fmOpenWrite) do
                  try
                     WriteBuffer( fido_cred_authdata_ptr(cred)^, fido_cred_authdata_len( cred ) );
                  finally
                         Free;
                  end;
             end;
        end;

        memLog.Lines.Add('Finished');
     finally
            fido_cred_free(cred);
            cred := nil;
     end;
end;

procedure TfrmFido2.btnCreateCredClick(Sender: TObject);
var credType : integer;
    challange, userId : Array[0..cChallangeSize-1] of byte;
    i : integer;
    cred : Pfido_cred_t;
    r : integer;
    uname : UTF8String;
    displName : UTF8String;
    residentKey, userVerification : boolean;
    ext : integer;
    pin : string;
    aPin : UTF8String;
    dev : Pfido_dev_t;
begin
     fWriteData := True;
     if fUSBPath = '' then
     begin
          memLog.Lines.Add('No path specified - click check key first');
          exit;
     end;

     if not InputQuery( 'PIN', 'Please input fido pin', pin) then
        exit;

     aPin := UTF8String( pin );
     ext := 0;  // := FIDO_EXT_HMAC_SECRET;

     cred := fido_cred_new;
     residentKey := True;
     userVerification := True;

     dev := fido_dev_new;
     assert(dev <> nil, 'Error no memory for fido device');
     try
        r := fido_dev_open(dev, PAnsiChar( fUSBPath ) );
        if r <> FIDO_OK then
           raise Exception.Create('Cannot open device ' + String(fUSBPath));

        cred := fido_cred_new;
        if cred = nil then
        begin
             memLog.Lines.Add('Failed to create credentials object');
             exit;
        end;
        try
           credType := COSE_ES256;

           Randomize;
           // create credentials for
           for i := 0 to cChallangeSize - 1 do
           begin
                challange[i] := Byte( Random(High(byte) + 1) );
                userId[i] := Random(High(Byte) + 1);
           end;

           // type
           fido_cred_set_type( cred, credType );

           // client data hash (or challange?!?!)
           r := fido_cred_set_clientdata_hash( cred, @challange[0], sizeof(challange));
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_cred_set_clientdata_hash: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           // relying party
           r := fido_cred_set_rp(cred, 'localhost', 'sweet home localhost');
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_cred_set_rp: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           // user
           uname := UTF8StrinG( edUsername.Text );
           displName := UTF8StrinG( edDisplayName.Text );

           r := fido_cred_set_user(cred, @userId[0], sizeof(userId), PAnsiChar( uname ), PAnsiChar(displName), nil );
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_cred_set_user: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           // set extension
           r := fido_cred_set_extensions( cred, ext );
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_cred_set_extensions: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           // resident key
           if residentKey then
           begin
                r := fido_cred_set_rk( cred, FIDO_OPT_TRUE );
                if r <> FIDO_OK then
                begin
                     memLog.Lines.Add( Format('Failed: fido_cred_set_rk: %s (%d)', [String(fido_strerr(r)), r]));
                     exit;
                end;
           end;

           // user verification
           if userVerification then
           begin
                fido_cred_set_uv( cred, FIDO_OPT_TRUE);
                if r <> FIDO_OK then
                begin
                     memLog.Lines.Add( Format('Failed: fido_cred_set_uv: %s (%d)', [String(fido_strerr(r)), r]));
                     exit;
                end;
           end;

           // ###########################################
           // #### credentials
           memLog.Lines.Add('Please verify by pushing the key');
           r := fido_dev_make_cred( dev, cred, PAnsiChar( aPin ) );
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_dev_make_cred: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           r := fido_dev_close(dev);
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_dev_close: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           fido_dev_free(dev);
           dev := nil;

           memLog.Lines.Add('All good - now verify the key and store the data...');

           // ###########################################
           // #### Verify
           move( userId, fuserId, sizeof(userId));
           move( challange, fcdh, sizeof(challange));
           VerifyCredentials( credType, fido_cred_fmt(cred),
                              fido_cred_authdata_ptr(cred), fido_cred_authdata_len(cred),
                              fido_cred_x5c_ptr(cred), fido_cred_x5c_len(cred), 
                              fido_cred_sig_ptr(cred), fido_cred_sig_len(cred),
                              residentKey, userVerification, ext);

        finally
               fido_cred_free(cred);
        end;
     finally
            if dev <> nil then
               fido_dev_free(dev);

            dev := nil;
     end;
end;

procedure TfrmFido2.btnInfoClick(Sender: TObject);
var dev : Pfido_dev_t;
    r : integer;
    flags : integer;
    flagsTxt : string;
    ci : Pfido_cbor_info_t;
    infoLen : integer;
    pinfo : PPAnsiChar;
    i : integer;
    pGuid0 : PByte;
    s : string;
    valuePtr : PBoolean;
    maxMsgSize : int64;
    pinProto : PByte;
    pinProtoLen : integer;
    retries : integer;
    pGuid1 : PGuid;
begin
     if fUSBPath = '' then
     begin
          memLog.Lines.Add('No path specified - click check key first');
          exit;
     end;

     dev := fido_dev_new;
     assert(dev <> nil, 'Error no memory for fido device');
     try
        r := fido_dev_open(dev, PAnsiChar( fUSBPath ) );
        if r <> FIDO_OK then
           raise Exception.Create('Cannot open device ' + String(fUSBPath));

        try
           MemLog.Lines.Add('Proto: $' + IntToHex( fido_dev_protocol( dev ), 2 ) );
           MemLog.Lines.Add('major: $' + IntToHex( fido_dev_major( dev ), 2 ) );
           MemLog.Lines.Add('minor: $' + IntToHex( fido_dev_minor( dev ), 2 ) );
           MemLog.Lines.Add('build: $' + IntToHex( fido_dev_build( dev ), 2 ) );

           r := fido_dev_get_retry_count(dev, retries);
           if r <> FIDO_OK then
           begin
                MemLog.Lines.Add( 'Getting number of retries failed with ' + IntToStr(r));
                memLog.Lines.Add( 'Message: ' + String( fido_strerr(r) ) );
           end
           else
               MemLog.Lines.Add('Number of retries: ' + IntToSTr( retries ) );

           flags := fido_dev_flags(dev);

           flagsTxt := '';
           flagsTxt := flagsTxt + ifthen((flags and FIDO_CAP_WINK) <> 0, 'wink,', 'nowink,');
           flagsTxt := flagsTxt + ifthen((flags and FIDO_CAP_CBOR) <> 0, 'cbor,', 'nocbor,');
           flagsTxt := flagsTxt + ifthen((flags and FIDO_CAP_NMSG) <> 0, 'nomsg,', 'msg,');

           memLog.Lines.Add('$' + IntToHex(flags, 2) + ': ' + flagsTxt);

           if fido_dev_is_fido2( dev ) then
           begin
                memLog.Lines.Add('Fido2 device found');

                ci := fido_cbor_info_new;
                if ci = nil then
                   raise Exception.Create('Error cannot create cbor info');
                try
                   r := fido_dev_get_cbor_info( dev, ci );
                   if r <> FIDO_OK then
                      raise Exception.Create('Failed to fetch cbor info');

                   infoLen := fido_cbor_info_versions_len( ci );
                   pinfo := fido_cbor_info_versions_ptr( ci );

                   assert(pInfo <> nil, 'Error no info array avail');
                   MemLog.Lines.Add('Versions');
                   for i := 0 to infoLen - 1 do
                   begin
                        memLog.Lines.Add('   ' + intToStr(i + 1) + ': ' + String( pinfo^ ) );
                        inc(pInfo);
                   end;

                   infoLen := fido_cbor_info_extensions_len( ci );
                   pInfo := fido_cbor_info_extensions_ptr( ci );
                   assert(pInfo <> nil, 'Error no info array avail');
                   MemLog.Lines.Add('Extensions');
                   for i := 0 to infoLen - 1 do
                   begin
                        memLog.Lines.Add('   ' + intToStr(i + 1) + ': ' + String( pinfo^ ) );
                        inc(pInfo);
                   end;

                   pGuid0 := fido_cbor_info_aaguid_ptr(ci);
                   infoLen := fido_cbor_info_aaguid_len( ci );
                   assert(pGuid0 <> nil, 'Error no info guid avail');

                   s := '';
                   memLog.Lines.Add('Guid len: ' + intToStr(infoLen) );
                   for i := 0 to infoLen - 1 do
                   begin
                        s := s + IntToHex( pGuid0^, 2 );
                        inc(pGuid0);
                   end;
                   memLog.Lines.Add('Guid: ' + s);

                   pGuid1 := PGuid(fido_cbor_info_aaguid_ptr(ci));
                   memLog.Lines.Add('Guid Str: ' + GUIDToString( pGuid1^ ) );


                   pInfo := fido_cbor_info_options_name_ptr(ci);
                   infoLen := fido_cbor_info_options_len(ci);
                   valuePtr := fido_cbor_info_options_value_ptr(ci);
                   assert(pInfo <> nil, 'No options name ptr avail');
                   assert(valuePtr <> nil, 'No option array avail');

                   MemLog.Lines.Add('options');
                   for i := 0 to infoLen - 1 do
                   begin
                        memLog.Lines.Add('   ' + intToStr(i + 1) + ': ' + String( pinfo^ ) + ' = ' + BoolToStr( valuePtr^, True ) );
                        inc(pInfo);
                        inc(valuePtr);
                   end;

                   maxMsgSize := fido_cbor_info_maxmsgsiz( ci );
                   memLog.Lines.Add('Max message size: ' + intToStr(maxMsgSize));

                   pinProto := fido_cbor_info_protocols_ptr( ci );
                   pinProtoLen := fido_cbor_info_protocols_len(ci);
                   s := '';
                   for i := 0 to pinProtoLen - 1 do
                   begin
                        s := s + IntToStr(pinProto^) + ',';
                        inc(pinProto);
                   end;

                   delete(s, Length(s), 1);
                   memLog.Lines.Add('Pin protocols: ' + s);

                finally
                       fido_cbor_info_free(ci);
                end;
           end
           else
               memLog.Lines.Add('No Fido2 device found');
        finally
               fido_dev_close(dev);
        end;
     finally
            fido_dev_free(dev);
     end;
end;

procedure TfrmFido2.btnSetPinClick(Sender: TObject);
var oldPin, newPin : string;
    aOldPin, aNewPin : UTF8String;
    dev : Pfido_dev_t;
    r : integer;
    poldpin : PAnsiChar;
begin
     if fUSBPath = '' then
     begin
          memLog.Lines.Add('No device defined - click check key first');
          exit;
     end;

     if not InputQuery( 'Pin', 'Input old Pin', oldPin) then
        exit;
     if not InputQuery( 'Pin', 'Input then new Pin', NewPin) then
        exit;

     aoldPin := UTF8String(oldPin);
     aNewPin := UTF8String(NewPin);

     poldPin := nil;
     if aoldPin <> '' then
        poldPin := PAnsiChar( aoldPin );

     dev := fido_dev_new;
     assert(dev <> nil, 'Error no memory for fido device');
     try
        r := fido_dev_open(dev, PAnsiChar( fUSBPath ) );
        if r <> FIDO_OK then
           raise Exception.Create('Cannot open device ' + String(fUSBPath));

        r := fido_dev_set_pin( dev, PAnsiChar(aNewPin), poldPin );
        if r <> FIDO_OK
        then
            memLog.Lines.Add( Format('Failed: fido_dev_make_cred: %s (%d)', [String(fido_strerr(r)), r]))
        else
            memLog.Lines.Add('Changing pin success');

        r := fido_dev_close(dev);
        if r <> FIDO_OK then
           memLog.Lines.Add( Format('Failed: fido_dev_close: %s (%d)', [String(fido_strerr(r)), r]));
     finally
            fido_dev_free(dev);
     end;
end;

procedure TfrmFido2.btnWebAuthVersionClick(Sender: TObject);
var avail : LongBool;
begin
     memLog.Lines.Add( Format('WebAuth verison: %d', [WebAuthNGetApiVersionNumber]));
     WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable( avail );

     memLog.Lines.Add('PlatformAuth Avail: ' + BoolToStr( avail, True) );
end;

procedure TfrmFido2.btnMakeAssertClick(Sender: TObject);
var dev : Pfido_dev_t;
    r : integer;
    i : integer;
    fidoAssert : Pfido_assert_t;
    sPin : AnsiString;
    pin : string;
    typ : integer;
    ext : integer;
begin
     if fUSBPath = '' then
     begin
          memLog.Lines.Add('No path specified - click check key first');
          exit;
     end;

     if not InputQuery( 'PIN', 'Please input fido pin', pin) then
        exit;

     ext := 0;
     typ := COSE_ES256;
     sPin := AnsiString( pin );

     for i := 0 to cChallangeSize - 1 do
         fcdh[i] := Byte( Random(High(byte) + 1) );

     fidoAssert := fido_assert_new;
     if not assigned(fidoAssert) then
        raise Exception.Create('fido_assert_new failed');

     try
        dev := fido_dev_new;
        assert(dev <> nil, 'Error no memory for fido device');
        try
           r := fido_dev_open(dev, PAnsiChar( fUSBPath ) );
           if r <> FIDO_OK then
              raise Exception.Create('Cannot open device ' + String(fUSBPath));

           // client data hash
           r := fido_assert_set_clientdata_hash(fidoAssert, @fcdh[0], length(fcdh));
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_assert_set_clientdata_hash: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           // relying party
           r := fido_assert_set_rp( fidoAssert, 'localhost');
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_assert_set_clientdata_hash: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           // user presence */
           if fUserPresence then
           begin
                r := fido_assert_set_up(fidoassert, FIDO_OPT_TRUE);
                if r <> FIDO_OK then
                begin
                     memLog.Lines.Add( Format('Failed: fido_assert_set_up: %s (%d)', [String(fido_strerr(r)), r]));
                     exit;
                end;
           end;
           if fUserVerification then
           begin
                r := fido_assert_set_uv(fidoassert, FIDO_OPT_TRUE);
                if r <> FIDO_OK then
                begin
                     memLog.Lines.Add( Format('Failed: fido_assert_set_uv: %s (%d)', [String(fido_strerr(r)), r]));
                     exit;
                end;
           end;

           // assertion...
           r := fido_dev_get_assert( dev, fidoAssert, PAnsiChar(sPin) );
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_assert_set_uv: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           fido_dev_close(dev);
        finally
               fido_dev_free(dev);
        end;

        if fido_assert_count(fidoAssert) <> 1 then
        begin
             memLog.Lines.Add( 'fido assert count : ' + intToStr(fido_assert_count(fidoAssert) )
                                      + ' signatures returned');
             exit;
        end;

        VerifyAssert( typ, fido_assert_authdata_ptr(fidoAssert, 0), fido_assert_authdata_len(fidoAssert, 0),
                      fido_assert_sig_ptr(fidoAssert, 0), fido_assert_sig_len(fidoAssert, 0), ext );
     finally
            fido_assert_free(fidoAssert);
     end;
end;

procedure TfrmFido2.VerifyAssert(typ: integer; authdata_ptr: PByte;
  authdata_len: integer; sig_ptr: PByte; sig_len: integer;
  ext: integer);
var pk : Pes256_pk_t;
    pkBuf : TBytes;
    pkFs : string;
    r : integer;
    fidoassert : Pfido_assert_t;
begin
     pkFs := edUsername.Text + '_pk.bin';
     if not FileExists(pkFs) then
     begin
          memLog.Lines.Add('Public key file not found for user:' + edUsername.Text);
          exit;
     end;

     with TFileStream.Create(pkFS, fmOpenRead) do
     try
        SetLength(pkBuf, Size);
        assert(length(pkBuf) > 0, 'Error empty file');
        ReadBuffer(pkBuf[0], Length(pkBuf));
     finally
            Free;
     end;

     pk := es256_pk_new;
     if pk = nil then
     begin
          memLog.Lines.Add('Error getting memory for es256');
          raise Exception.Create('Error getting memory for es256');
     end;
     try
        r := es256_pk_from_ptr( pk, @pkBuf[0], Length(pkBuf) );
        if r <> FIDO_OK then
        begin
             memLog.Lines.Add( Format('Failed: es256_pk_from_ptr: %s (%d)', [String(fido_strerr(r)), r]));
             exit;
        end;

        fidoAssert := fido_assert_new;
        if fidoAssert = nil then
        begin
             memLog.Lines.Add('fido_assert_new failed');
             exit;
        end;
        try
           // client data hash
           r := fido_assert_set_clientdata_hash(fidoAssert, @fcdh[0], length(fcdh));
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_assert_set_clientdata_hash: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           // relying party
           r := fido_assert_set_rp( fidoAssert, 'localhost');
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_assert_set_clientdata_hash: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           // authdata
           r := fido_assert_set_count(fidoassert, 1);
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_assert_set_count: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;
           r := fido_assert_set_authdata(fidoAssert, 0, authdata_ptr, authdata_len);
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_assert_set_authdata: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           // extension
           r := fido_assert_set_extensions(fidoAssert, ext);
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_assert_set_extensions: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           // user presence */
           if fUserPresence then
           begin
                r := fido_assert_set_up(fidoassert, FIDO_OPT_TRUE);
                if r <> FIDO_OK then
                begin
                     memLog.Lines.Add( Format('Failed: fido_assert_set_up: %s (%d)', [String(fido_strerr(r)), r]));
                     exit;
                end;
           end;
           if fUserVerification then
           begin
                r := fido_assert_set_uv(fidoassert, FIDO_OPT_TRUE);
                if r <> FIDO_OK then
                begin
                     memLog.Lines.Add( Format('Failed: fido_assert_set_uv: %s (%d)', [String(fido_strerr(r)), r]));
                     exit;
                end;
           end;
           r := fido_assert_set_sig(fidoassert, 0, sig_ptr, sig_len);
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_assert_set_sig: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           r := fido_assert_verify(fidoassert, 0, typ, pk);
           if r <> FIDO_OK then
           begin
                memLog.Lines.Add( Format('Failed: fido_assert_verify: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           memLog.Lines.Add('verify ok');
        finally
               fido_assert_free(fidoAssert);
        end;
     finally
            es256_pk_free(pk);
     end;
end;

procedure TfrmFido2.btnResetClick(Sender: TObject);
var dev : Pfido_dev_t;
    r : integer;
begin
     if MessageDlg( 'Do you really want to reset the key to factory defaults?' + #13#10 +
                    'To reset start this routine within 5 seconds after attaching the device!', mtConfirmation, [mbYes, mbNo], -1) = mrNo then
        exit;

     btnCheckKeyClick(nil);
     if fUSBPath = '' then
     begin
          memLog.Lines.Add('No device defined - click check key first');
          exit;
     end;

     dev := fido_dev_new;
     assert(dev <> nil, 'Error no memory for fido device');
     try
        r := fido_dev_open(dev, PAnsiChar( fUSBPath ) );
        if r <> FIDO_OK then
           raise Exception.Create('Cannot open device ' + String(fUSBPath));

        r := fido_dev_reset( dev );
        if r <> FIDO_OK
        then
            memLog.Lines.Add( Format('Failed: fido_dev_make_cred: %s (%d)', [String(fido_strerr(r)), r]))
        else
            memLog.Lines.Add( 'Successfully reset the device');

        r := fido_dev_close(dev);
        if r <> FIDO_OK then
           memLog.Lines.Add( Format('Failed: fido_dev_close: %s (%d)', [String(fido_strerr(r)), r]));


     finally
            fido_dev_free(dev);
     end;
end;

procedure TfrmFido2.btnCredmanClick(Sender: TObject);
var devList : TFidoDevList;
    cnt: Integer;
    pin : string;
    errStr : string;
    credMan : TFido2CredentialManager;
begin
     devList := TFidoDevice.DevList;
     assert(assigned(devList), 'error no device found');

     try
        memLog.Lines.Add(IntTostr(devList.Count) + ' devices found');
        for cnt := 0 to devList.Count - 1 do
        begin
             memLog.Lines.Add('Device V' + devList[cnt].Firmware);

             if devList[cnt].IsFido2 then
             begin
                  if not InputQuery( 'Pin', 'Input then new Pin', Pin) then
                     continue;
                  credman := TFido2CredentialManager.Create;
                  try
                     if credman.Open( devList[cnt], pin, errStr) then
                     begin
                          memLog.Lines.Add('Num remaining keys: ' + IntToStr( credman.NumResidentKeysRemain ) );
                          memLog.Lines.Add('Num RK keys: ' + inttostr( credman.NumResidentKeys ) );
                     end
                     else
                         memLog.lines.Add('No credmanager avail: ' + errStr);
                  finally
                         credman.Free;
                  end;
             end
             else
                 memLog.Lines.Add('No fido2 device');

             memLog.Lines.Add('');
        end;
     finally
            devList.Free;
     end;
end;

procedure TfrmFido2.btnCreadCredObjClick(Sender: TObject);
var devList : TFidoDevList;
    cred : TFidoCredCreate;
    pin : string;
begin
     devList := TFidoDevice.DevList;

     try
        if devList.Count > 0 then
        begin
             if not InputQuery( 'PIN', 'Please input fido pin', pin) then
                exit;

             cred := TFidoCredCreate.Create;
             try
                cred.CreateRandomUid(64);
                cred.ResidentKey := FIDO_OPT_TRUE;
                cred.UserIdentification := FIDO_OPT_TRUE;
                cred.UserName := edUsername.Text;
                cred.UserDisplayName := edDisplayName.Text;

                // use defaults for the rest
                if cred.CreateCredentialsAndVerify(devList[0], pin) then
                begin
                     memLog.Lines.Add('Credentials created');
                     cred.SavePKToFile( cred.UserName + '_obj_pk.bin' );
                     cred.SaveUIDToFile(cred.UserName + '_obj_uid.bin' );
                     cred.SaveCredIDToFile( cred.UserName + '_obj_credId.bin');
                end
                else
                    memLog.Lines.Add('Credentials failed');
             finally
                    cred.Free;
             end;
        end;
     finally
            devList.Free;
     end;

end;

procedure TfrmFido2.Button2Click(Sender: TObject);
var devList : TFidoDevList;
    i,j : Integer;
begin
     devList := TFidoDevice.DevList;

     try
        memLog.Lines.Add('Found ' + inttoStr(devList.Count) + ' keys');

        for i := 0 to devList.Count - 1 do
        begin
             MemLog.Lines.Add('Serial: ' + devList[i].Firmware);
             MemLog.Lines.Add('ManufactStr: ' + devList[i].ManufactStr);
             MemLog.Lines.Add('ProductInfo: ' + devList[i].ProductInfo);
             MemLog.Lines.Add('Product: ' + IntTostr(devList[i].Product));
             MemLog.Lines.Add('Vendor: ' + IntToStr(devList[i].vendor));
             MemLog.Lines.Add('Protocol: '  + intToSTr(devList[i].Protocol) );
             MemLog.Lines.Add('Retry cnt: ' + intToStr(devList[i].RetryCnt) );

             if dfWink in devList[i].Flags then
                MemLog.Lines.Add('Flag wink');
             if dfCBOR in devList[i].Flags then
                MemLog.Lines.Add('Flag CBOR');
             if dfMSg in devList[i].Flags then
                MemLog.Lines.Add('Flag Msg');

             memLog.Lines.Add( 'is Fido2: ' + BoolToStr( devList[i].IsFido2, True ) );
             if devList[i].CBOR <> nil then
             begin
                  memLog.Lines.Add('MaxMsgSize: ' + IntToStr(devList[i].CBOR.MaxMsgSize));
                  memLog.Lines.Add('UUID: ' + devList[i].CBOR.UUIDToGuid);

                  memLog.Lines.Add('Options:' );
                  for j := 0 to devList[i].CBOR.OptionsCnt - 1 do
                  begin
                       memLog.Lines.Add(devList[i].CBOR.Options[j].Name + ': ' + boolToStr( devList[i].CBOR.Options[j].Value, True ) );
                  end;

                  memLog.Lines.Add('Versions: ' + devList[i].CBOR.Versions.CommaText );
                  memLog.Lines.Add('Extensions: ' + devList[i].CBOR.Extensions.CommaText );
             end;
        end;
     finally
            devList.Free;
     end;
end;

procedure TfrmFido2.btnAssertObjClick(Sender: TObject);
var devList : TFidoDevList;
    i : Integer;
    assert : TFidoAssert;
    verify : TFidoAssertVerify;
    assertRes : boolean;
    cnt : integer;
    res : boolean;
    pin : string;
begin
     devList := TFidoDevice.DevList;

     try
        memLog.Lines.Add('Found ' + inttoStr(devList.Count) + ' keys');

        if devList.Count > 0 then
        begin
             if not InputQuery( 'PIN', 'Please input fido pin', pin) then
                exit;

             assert := TFidoAssert.Create;
             try
                assert.UserVerification := FIDO_OPT_TRUE;
                assert.UserPresence := FIDO_OPT_TRUE;
                assert.Fmt := fmFido2;
                assert.CreateRandomCID;

                assertRes := assert.Perform( devList[0], pin, cnt);
                memLog.Lines.Add( Format('Perform returned: %s, with cnt: %d' , [BoolToStr( assertRes, True), cnt] ) );

                if assertRes then
                begin
                     // verify the assertion
                     verify := TFidoAssertVerify.Create;
                     try
                        verify.LoadPKFromFile(edUsername.Text + '_obj_pk.bin');
                        verify.ClientDataHash := assert.ClientDataHash;
                        verify.Fmt := fmFido2;
                        verify.UserPresence := FIDO_OPT_TRUE;
                        verify.UserVerification := FIDO_OPT_TRUE;

                        for i := 0 to cnt - 1 do
                        begin
                             res := verify.Verify( assert.AuthData[i], assert.Sig[i] );

                             memLog.Lines.Add(IntToStr( i + 1) + ': Verify returned: ' + BoolToStr( res, True ) );
                             if not res then
                                memLog.Lines.Add( 'Err Msg: ' + verify.ErrorMsg);
                        end;
                     finally
                            verify.Free;
                     end;
                end
                else
                    memLog.Lines.Add('err msg: ' + assert.ErrorMsg);
             finally
                    assert.Free;
             end;
        end;

     finally
            devList.Free;
     end;


end;

end.
