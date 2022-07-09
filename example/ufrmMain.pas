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
  Dialogs, StdCtrls, ExtCtrls, Fido2;

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
    btnKeyInfo: TButton;
    btnAssertObj: TButton;
    timPolStatus: TTimer;
    btnPollTouch: TButton;
    chkHMACSecret: TCheckBox;
    Label1: TLabel;
    chkCredLargeBlock: TCheckBox;
    chkResidentKey: TCheckBox;
    chkVerbose: TCheckBox;
    edBlob: TEdit;
    Label2: TLabel;
    cboDevs: TComboBox;
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
    procedure btnKeyInfoClick(Sender: TObject);
    procedure btnAssertObjClick(Sender: TObject);
    procedure btnPollTouchClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure timPolStatusTimer(Sender: TObject);
    procedure chkVerboseClick(Sender: TObject);
    procedure edBlobExit(Sender: TObject);
  private
    { Private-Deklarationen }
    fWriteData : boolean;
    fUserPresence : boolean;
    fUserVerification : boolean;
    fUSBPath : AnsiString;
    fuserId : Array[0..cChallangeSize-1] of byte;
    fcdh : Array[0..cChallangeSize-1] of byte;
    fTouchIter : integer;
    fDevList : TFidoDevList;
    fVerbose : boolean;

    procedure InitDevCombo;
    function GetSelDevCombo( devList : TFidoDevList ) : TFidoDevice;
    procedure VerifyCredentials( typ : integer; fmt : PAnsiChar;
              authdataPtr : PByte; authDataLen : integer;
              x509Ptr : PByte; x509Len : integer;
              sigPtr : PByte; sigLen : integer;
              rk : boolean; uv : boolean; ext : integer);

    function VerifyAssert(typ : integer; authdata_ptr : PByte; authdata_len : integer;
                           sig_ptr : PByte; sig_len : integer;
                           ext : integer) : boolean;
    procedure onFidoDLLLog(msg : string);
  public
    { Public-Deklarationen }
  end;

var
  frmFido2: TfrmFido2;

implementation

uses Fido2dll, webauthn, StrUtils, authData, cbor;

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
     fUserVerification := true;
     fido_init(cFidoInitDebug);

     fVerbose := chkVerbose.Checked;
     InitFidoLogger( onFidoDLLLog );

     InitDevCombo;
end;

procedure TfrmFido2.FormDestroy(Sender: TObject);
begin
     fDevList.Free;
end;

function TfrmFido2.GetSelDevCombo(devList: TFidoDevList): TFidoDevice;
var idx : integer;
    productInfo : string;
begin
     productInfo := cboDevs.Text;
     Result := nil;

     // check shortcut
     if (cboDevs.ItemIndex >= 0) and (devList.Count = cboDevs.Items.Count) and (devList[cboDevs.ItemIndex].ProductInfo = productInfo) then
     begin
          Result := devList[cboDevs.ItemIndex];
     end
     else
     begin
          for idx := 0 to devList.Count - 1 do
          begin
               if devList[idx].ProductInfo = productInfo then
               begin
                    Result := devList[idx];
                    break;
               end;
          end;
     end;
end;

procedure TfrmFido2.InitDevCombo;
var devList : TFidoDevList;
    i : integer;
begin
     cboDevs.Clear;

     devList := TFidoDevice.DevList;
     try
        for i := 0 to devList.Count - 1 do
            cboDevs.AddItem(devList[i].ProductInfo, nil);
     finally
            devList.Free;
     end;
end;

procedure TfrmFido2.onFidoDLLLog(msg: string);
begin
     if fVerbose then
        memLog.Lines.Add('FidoDll: ' + msg);
end;

procedure TfrmFido2.timPolStatusTimer(Sender: TObject);
var status : integer;
    dev : TFidoDevice;
begin
     timPolStatus.Enabled := False;

     dev := GetSelDevCombo(fDevList);

     if dev = nil then
     begin
          FreeAndNil(fDevList);
          exit;
     end;

     inc(fTouchIter);
     if fTouchIter > 50 then
     begin
          dev.Cancel;
          FreeAndNil(fDevList);
     end
     else
     begin
          status := dev.GetTouchStatus( 50 );
          memLog.Lines.Add('Touch Status: ' + IntToStr(status) );
          if status <> 0 then
          begin
               memLog.Lines.Add('Touched');
               dev.Cancel;
               FreeAndNil(fDevList);
          end
          else
              timPolStatus.Enabled := True;
     end;
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

             if (ext and FIDO_EXT_LARGEBLOB_KEY) <> 0 then
             begin
                  if fido_cred_largeblob_key_len( cred ) = 0
                  then
                      memLog.Lines.Add('No largeblob found although set in options')
                  else
                  begin
                       with TFileStream.Create(edUsername.Text + '_largeblob.bin', fmCreate or fmOpenWrite) do
                       try
                          WriteBuffer( fido_cred_largeblob_key_ptr(cred)^, fido_cred_largeblob_key_len( cred ) );
                       finally
                              Free;
                       end;
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
    blobData : UTF8String;
begin
     fWriteData := True;
     if fUSBPath = '' then
     begin
          memLog.Lines.Add('No path specified - click check key first');
          exit;
     end;

     if edBlob.Text <> '' then
        chkResidentKey.Checked := True;
     ext := 0;
     if chkHMACSecret.Checked then
        ext := ext or FIDO_EXT_HMAC_SECRET;
     if chkCredLargeBlock.Checked then
        ext := ext or FIDO_EXT_LARGEBLOB_KEY;
     if edBlob.Text <> '' then
        ext := ext or FIDO_EXT_CRED_BLOB;

     residentKey := chkResidentKey.Checked;

     dev := fido_dev_new;
     assert(dev <> nil, 'Error no memory for fido device');
     try
        r := fido_dev_open(dev, PAnsiChar( fUSBPath ) );
        if r <> FIDO_OK then
           raise Exception.Create('Cannot open device ' + String(fUSBPath));

        userVerification := fido_dev_has_uv(dev);
        if fido_dev_has_pin( dev ) then
           if not InputQuery( 'PIN', 'Please input fido pin', pin) then
              exit;

        aPin := UTF8String( pin );

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


           // blob
           if edBlob.Text <> '' then
           begin
                blobData := UTF8String( edBlob.Text );
                r := fido_cred_set_blob( cred, @blobData[1], Length(blobData) );
                if r <> FIDO_OK then
                begin
                     memLog.Lines.Add( Format('Failed: fido_cred_set_blob: %s (%d)', [String(fido_strerr(r)), r]));
                     exit;
                end;
           end;

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
           if userVerification and fido_dev_has_uv( dev ) then
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
    maxCredCntLst : int64;
    maxcredidlen : int64;
    maxcredbloblen : int64;
    fwversion : int64;
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
           memLog.Lines.Add('Is WinHello: ' + BoolToStr(fido_dev_is_winhello( dev ), True));

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

                   maxCredCntLst := fido_cbor_info_maxcredcntlst(ci);
                   memLog.Lines.Add('maxCredCntLst: ' + IntToStr( maxCredCntLst) );
                   maxcredidlen := fido_cbor_info_maxcredidlen(ci);
                   memLog.Lines.Add('maxcredidlen: ' + IntToStr( maxcredidlen) );
                   maxcredbloblen := fido_cbor_info_maxcredbloblen(ci);
                   memLog.Lines.Add('maxcredbloblen: ' + IntToStr( maxcredbloblen) );
                   fwversion := fido_cbor_info_fwversion(ci);
                   memLog.Lines.Add('fwversion: ' + IntToStr( fwversion) );

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
    assertCnt : integer;
begin
     if fUSBPath = '' then
     begin
          memLog.Lines.Add('No path specified - click check key first');
          exit;
     end;

     ext := 0;
     if chkHMACSecret.Checked then
        ext := ext or FIDO_EXT_HMAC_SECRET;
     if chkCredLargeBlock.Checked then
        ext := ext or FIDO_EXT_LARGEBLOB_KEY;

     typ := COSE_ES256;
     pin := '';

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

           if fido_dev_has_pin(dev) then
              if not InputQuery( 'PIN', 'Please input fido pin', pin) then
                 exit;

           sPin := AnsiString( pin );

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
                memLog.Lines.Add( Format('Failed: fido_dev_get_assert: %s (%d)', [String(fido_strerr(r)), r]));
                exit;
           end;

           fido_dev_close(dev);
        finally
               fido_dev_free(dev);
        end;

        assertCnt := fido_assert_count(fidoAssert);
        memLog.Lines.Add( 'fido assert count : ' + intToStr( assertCnt )
                                      + ' signatures returned');

        while assertCnt > 0 do
        begin
             memLog.Lines.Add('Checking index ' + IntToStr(assertCnt - 1));

             if VerifyAssert( typ, fido_assert_authdata_ptr(fidoAssert, assertCnt - 1),
                              fido_assert_authdata_len(fidoAssert, assertCnt - 1),
                              fido_assert_sig_ptr(fidoAssert, assertCnt - 1),
                              fido_assert_sig_len(fidoAssert, assertCnt - 1), ext )
             then
                 break;

             dec(assertCnt);
        end;

        if assertCnt > 0
        then
            memLog.Lines.Add('Success on item nr ' + IntToStr(assertCnt))
        else
            memLog.Lines.Add('Assertion failed');
     finally
            fido_assert_free(fidoAssert);
     end;
end;

procedure TfrmFido2.btnPollTouchClick(Sender: TObject);
var dev : TFidoDevice;
begin
     if Assigned(fdevList) then
        fDevList.Free;

     fdevList := TFidoDevice.DevList;

     dev := GetSelDevCombo(fdevlist);
     if dev <> nil then
     begin
          fTouchIter := 0;
          dev.BeginTouch;

          timPolStatus.Enabled := True;
     end
     else
         FreeAndNil(fDevList);
end;

function TfrmFido2.VerifyAssert(typ: integer; authdata_ptr: PByte;
  authdata_len: integer; sig_ptr: PByte; sig_len: integer;
  ext: integer) : boolean;
var pk : Pes256_pk_t;
    pkBuf : TBytes;
    pkFs : string;
    r : integer;
    fidoassert : Pfido_assert_t;
begin
     Result := False;
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

           Result := True;
           memLog.Lines.Add('verify ok');

           // ###########################################
           // #### Fetch blob
           if chkCredLargeBlock.Checked then
           begin
                if fido_assert_largeblob_key_len(fidoAssert, 0) > 0
                then
                    memLog.Lines.Add( Base64URLEncode(fido_assert_largeblob_key_ptr(fidoassert, 0), fido_assert_largeblob_key_len(fidoAssert, 0)) )
                else
                    memLog.Lines.Add('No largeblob data');
           end;
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
    pin : string;
    errStr : string;
    credMan : TFido2CredentialManager;
    dev : TFidoDevice;
begin
     devList := TFidoDevice.DevList;
     assert(assigned(devList), 'error no device found');

     try
        memLog.Lines.Add(IntTostr(devList.Count) + ' devices found');
        dev := GetSelDevCombo(devList);

        if dev <> nil then
        begin
             memLog.Lines.Add('Device V' + dev.Firmware);

             if dev.IsFido2 then
             begin
                  if not InputQuery( 'Pin', 'Input then new Pin', Pin) then
                     exit;
                  credman := TFido2CredentialManager.Create;
                  try
                     if credman.Open( dev, pin, errStr) then
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
    dev : TFidoDevice;
begin
     devList := TFidoDevice.DevList;

     try
        dev := GetSelDevCombo(devList);

        if dev <> nil then
        begin
             if not InputQuery( 'PIN', 'Please input fido pin', pin) then
                exit;

             cred := TFidoCredCreate.Create;
             try
                cred.CreateRandomUid(64);
                if chkResidentKey.Checked = False then
                begin
                     if MessageDlg('Resident key option not set - assertion may fail...' + #13#10 +
                                   'Do you want to set the option?', mtConfirmation, [mbYes, mbNo], -1) = mrYes
                     then
                         chkResidentKey.Checked := True;
                end;

                if chkResidentKey.Checked
                then
                    cred.ResidentKey := FIDO_OPT_TRUE
                else
                    cred.ResidentKey := FIDO_OPT_FALSE;
                cred.UserIdentification := FIDO_OPT_TRUE;
                cred.UserName := edUsername.Text;
                cred.UserDisplayName := edDisplayName.Text;

                // use defaults for the rest
                if cred.CreateCredentialsAndVerify(dev, pin) then
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

procedure TfrmFido2.btnKeyInfoClick(Sender: TObject);
var devList : TFidoDevList;
    j : Integer;
    dev : TFidoDevice;
begin
     devList := TFidoDevice.DevList;
     if devList.Count <> cboDevs.Items.Count then
        InitDevCombo;
     try
        memLog.Lines.Add('Found ' + inttoStr(devList.Count) + ' keys');
        dev := GetSelDevCombo(devList);

        if dev = nil then
        begin
             memLog.Lines.Add('No device selected');
             exit;
        end;

        MemLog.Lines.Add('Serial: ' + dev.Firmware);
        MemLog.Lines.Add('ManufactStr: ' + dev.ManufactStr);
        MemLog.Lines.Add('ProductInfo: ' + dev.ProductInfo);
        MemLog.Lines.Add('Product: ' + IntTostr(dev.Product));
        MemLog.Lines.Add('Vendor: ' + IntToStr(dev.vendor));
        MemLog.Lines.Add('Protocol: '  + intToSTr(dev.Protocol) );
        MemLog.Lines.Add('Retry cnt: ' + intToStr(dev.RetryCnt) );
        MemLog.Lines.Add('Supports Cred Manager: ' + BoolToStr(dev.SupportCredManager, True));
        MemLog.Lines.Add('Supports Cred Protection: ' + BoolToStr(dev.SupportCredProtection, True));
        MemLog.Lines.Add('Supports User Verification: ' + BoolToStr(dev.SupportUserVerification, True));
        MemLog.Lines.Add('Supports Permissions: ' + BoolToStr(dev.SupportPermissions, True));
        MemLog.Lines.Add('User verification retry count: ' + IntToStr(dev.UserVerificatinRetryCount));
        MemLog.Lines.Add('Is WinHello: ' + BoolToStr(dev.IsWinHello, True));

        if dfWink in dev.Flags then
           MemLog.Lines.Add('Flag wink');
        if dfCBOR in dev.Flags then
           MemLog.Lines.Add('Flag CBOR');
        if dfMSg in dev.Flags then
           MemLog.Lines.Add('Flag Msg');

        memLog.Lines.Add( 'is Fido2: ' + BoolToStr( dev.IsFido2, True ) );
        if dev.CBOR <> nil then
        begin
             memLog.Lines.Add('MaxMsgSize: ' + IntToStr(dev.CBOR.MaxMsgSize));
             memLog.Lines.Add('UUID: ' + dev.CBOR.UUIDToGuid);

             memLog.Lines.Add('Options:' );
             for j := 0 to dev.CBOR.OptionsCnt - 1 do
             begin
                  memLog.Lines.Add(dev.CBOR.Options[j].Name + ': ' + boolToStr( dev.CBOR.Options[j].Value, True ) );
             end;

             memLog.Lines.Add('Cose algorithms:' + IntToStr(dev.CBOR.CoseAlgorithmCnt));
             for j := 0 to dev.CBOR.CoseAlgorithmCnt - 1 do
                 memLog.Lines.Add(IntToStr(dev.CBOR.CoseAlgorithms[j]));

             memLog.Lines.Add('Versions: ' + dev.CBOR.Versions.CommaText );
             memLog.Lines.Add('Extensions: ' + dev.CBOR.Extensions.CommaText );

             memLog.Lines.Add('Cred protect: ' + BoolToStr(dev.SupportCredProtection, True));
             memLog.Lines.Add('User verification support: ' + BoolToStr(dev.SupportUserVerification, True));
             memLog.Lines.Add('Pin support: ' + BoolToStr(dev.SupportPin, True));
             memLog.Lines.Add('Credential manager support: ' + BoolToStr(dev.SupportCredManager, True));

             memLog.Lines.Add('MaxBlobLen: ' + IntTostr(dev.CBOR.maxBlobLen) );
             memLog.Lines.Add('MaxLargeBlobLen: ' + IntToStr(dev.CBOR.MaxLargeBlob) );
             memLog.Lines.Add('FWVersion: ' + IntTostr(dev.CBOR.FWVersion) );
             memLog.Lines.Add('MaxCredCntList: ' + IntTostr(dev.CBOR.MaxCredCntList) );
             memLog.Lines.Add('MaxCredIDLen: ' + IntTostr(dev.CBOR.MaxCredIDLen) );
             memLog.Lines.Add('Blob Support: ' + BoolToStr(dev.HasBlobSupport, True ) );
        end;
     finally
            devList.Free;
     end;
end;

procedure TfrmFido2.chkVerboseClick(Sender: TObject);
begin
     fVerbose := chkVerbose.Checked;
end;

procedure TfrmFido2.edBlobExit(Sender: TObject);
begin
     if edBlob.Text <> '' then
        chkResidentKey.Checked := True;
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
    dev : TFidoDevice;
begin
     devList := TFidoDevice.DevList;

     try
        memLog.Lines.Add('Found ' + inttoStr(devList.Count) + ' keys');

        dev := GetSelDevCombo(devList);

        if dev <> nil then
        begin
             if not InputQuery( 'PIN', 'Please input fido pin', pin) then
                exit;

             assert := TFidoAssert.Create;
             try
                assert.UserVerification := FIDO_OPT_TRUE;
                assert.UserPresence := FIDO_OPT_TRUE;
                assert.Fmt := fmFido2;
                assert.CreateRandomCID;

                assertRes := assert.Perform( dev, pin, cnt);
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
                             res := verify.Verify( assert.AuthData[i], assert.Sig[i], assert.Extensions );

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
