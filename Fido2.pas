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

unit Fido2;

interface

uses SysUtils, Classes, Fido2dll, Generics.Collections, cbor;

type
  EFidoBaseException = class(Exception);
  EFidoAllocException = class(EFidoBaseException);
  EFidoPropertyException = class(EFidoBaseException);
  EFidoException = class(EFidoBaseException)
  private
    fErrCode : integer;
  public
    property ErrCode : integer read fErrCode;

    constructor Create( aErrCode : integer );
  end;

type
  TFidoChallenge = Array[0..31] of byte;    // from https://fidoalliance.org/specs/fido-v2.0-rd-20170927/fido-client-to-authenticator-protocol-v2.0-rd-20170927.html
  TFidoUserId = Array[0..31] of byte; // here used as the same type as the challange
  TFidoSHA256Hash = Array[0..31] of byte;

  TFidoLogMsg = procedure(msg : string) of Object;

const cMaxSmallBlobLen = 32;

// ###################################################
// #### Encapsulation of the fido_cbor_xxx functions
// ###################################################
type
  TFido2CBOROption = class(TObject)
  private
    fName : string;
    fValue : boolean;
  public
    property Name : string read fName;
    property Value : boolean read fValue;

    constructor Create( aName : string; aVal: boolean);
  end;
  TFido2CBOR = class(TObject)
  private
    fCBORVersions : TStringList;
    fCBORExtension : TStringList;
    fCBORTransports : TStringList;
    fCBORCertNames : TStringList;
    fCBORUUID : TBytes;
    fCBORGuid : string;
    fCBORCose : Array of integer;
    fCBOROptions : Array of TFido2CBOROption;
    fCBORPinProtocols : TBytes;
    fCBORmaxMsgSize : UInt64;
    fCBORmaxLargeBlob : UInt64;
    fCBORMaxCredCntLst : UInt64;
    fCBORMaxCredidlen : UInt64;
    fCBORMaxBlobLen : UInt64;
    fCBORFWVersion : UInt64;

    fCBORMaxrpidMinpinlen : UINT64;
    fCBORMinPinLen : UINT64;
    fCBORUVAttempts : UINT64;
    fCBORUVMOdality : UINT64;
    fCBORRKRemaining : UINT64;
    fCBORNewPinRequired : boolean;

    procedure ReadProperties( dev : PFido_dev_t );
    function GetOption(index: integer): TFido2CBOROption;
    function GetOptionsCnt: integer;
    function GetCoseAlgorithm(index: integer): integer;
    function GetCoseAlgorithmCnt: integer;
    function GetCertName(index: Integer): string;
    function GetCertNameLen: integer;
  public
    property MaxMsgSize : UInt64 read fCBORmaxMsgSize;
    property UUID : TBytes read fCBORUUID;
    property OptionsCnt : integer read GetOptionsCnt;
    property Options[index : integer] : TFido2CBOROption read GetOption;
    property CertName[index : Integer] : string read GetCertName;
    property CertNameLen : integer read GetCertNameLen;
    property Versions : TStringList read fCBORVersions;
    property Extensions : TStringList read fCBORExtension;
    property PinProtocols : TBytes read fCBORPinProtocols;
    property MaxBlobLen : UInt64 read fCBORMaxBlobLen;
    property MaxLargeBlob : UInt64 read fCBORmaxLargeBlob;
    property FWVersion : UInt64 read fCBORFWVersion;
    property MaxCredCntList : UInt64 read fCBORMaxCredCntLst;
    property MaxCredIDLen : UInt64 read fCBORMaxCredidlen;
    property CoseAlgorithmCnt : integer read GetCoseAlgorithmCnt;
    property CoseAlgorithms[index : integer] : integer read GetCoseAlgorithm;


    function UUIDToGuid : String;

    constructor Create( dev : PFido_dev_t );
    destructor Destroy; override;
  end;

// ###################################################
// #### Fido device
// ###################################################

type
  TFido2DevFlag = (dfWink, dfCBOR, dfMSg);
  TFidoDevFlags = set of TFido2DevFlag;
type
  TFidoDevice = class;
  TFidoDevList = TObjectList<TFidoDevice>;
  TFidoDevice = class(TObject)
  private
    fDev : Pfido_dev_t;
    fUSBPath : UTF8String;
    fManufactStr : string;
    fProductInfo : string;
    fVendor : integer;
    fProduct : integer;

    fProtocol : byte;

    fDevMajor : integer;
    fDevMinor : integer;
    fDevBuild : integer;
    fRetryCnt : integer;
    fSupportPin : boolean;
    fSupportCredProtection : boolean;
    fSupportPermissions : boolean;

    fDevFlags : TFidoDevFlags;
    fIsFido2 : boolean;

    fCbor : TFido2CBOR;
    fUVRetryCnt: integer;
    fHasUserVerification: boolean;
    fSupportUserVerification: boolean;
    fSupportCredManager: boolean;
    fHasBlobSupport: boolean;
    fIsWinHello: boolean;

    procedure OpenDevice;
    procedure CloseDevice;
    function GetFirmware: string;
    function GetHasPin: boolean;
    function GetLargeBlobRaw: TBytes;
    function GetLargeBlob: TCborItem;
    function GetLargeBlobKey(key: TBytes): TBytes;
  protected
    procedure ReadProperties(di : Pfido_dev_info_t);
    procedure ReadDev;
  public
    // fetch the complete list of keys -> use this as the base enumeration
    // note the function needs to be run in Administrator mode!
    class function DevList : TFidoDevList;

    property ManufactStr : string read fManufactStr;
    property ProductInfo : string read fProductInfo;
    property Vendor : integer read fVendor;
    property Product : integer read fProduct;
    property Firmware : string read GetFirmware;
    property USBPath : UTF8String read fUSBPath;
    property RetryCnt : integer read fRetryCnt;
    property UserVerificatinRetryCount : integer read fUVRetryCnt;
    property HasUserVerification : boolean read fHasUserVerification;
    property Protocol : byte read fProtocol;
    property Flags : TFidoDevFlags read fDevFlags;
    property HasPin : boolean read GetHasPin;
    property SupportPin : boolean read fSupportPin;
    property SupportCredProtection : boolean read fSupportCredProtection;
    property SupportUserVerification : boolean read fSupportUserVerification;
    property SupportCredManager : boolean read fSupportCredManager;
    property SupportPermissions : boolean read fSupportPermissions;
    property DevHdl : Pfido_dev_t read fDev;

    // only valid on fido2 devices
    property CBOR : TFido2CBOR read FCBOR;
    property IsFido2 : boolean read fIsFido2;
    property IsWinHello : boolean read fIsWinHello;
    property HasBlobSupport : boolean read fHasBlobSupport;

    property LargeBlobRaw : TBytes read GetLargeBlobRaw;
    property LargeBlobArr : TCborItem read GetLargeBlob;
    property LargeBlob[ key : TBytes ] : TBytes read GetLargeBlobKey;

    procedure SetLargeBlobArr( data : TBytes; pin : string ); overload;
    procedure SetLargeBlob( key, data : TBytes; pin : string );
    procedure SetLargeBlobArr( cborData : TCborItem; pin : string ); overload;
    procedure SetTimeout( ms : integer );

    procedure ForceFido2;
    procedure ForceU2F;

    function SetPin( oldPin : string; newPin : string; var ErrStr : string) : boolean;
    // special Yubico Reset procedure: This function may only be called within 5 seconds after
    // attaching the key.
    procedure Reset;

    // touch control
    procedure BeginTouch;
    function GetTouchStatus(waitMs : integer = 0) : integer;

    // cancels the latest device operation (waiting for user interaction)
    procedure Cancel;

    // constructors
    constructor CreateFromPath( usbPath : String );
    constructor CreateFromDevInfo( di : Pfido_dev_info_t );

    destructor Destroy; override;
  end;

type
  TFidoBiometricTemplate = class(TObject)
  private
    fTemplate : Pfido_bio_template_t;
    fOwnsTemplate : boolean;
    function GetID: TBytes;
    function GetString: string;
    procedure SetId(const Value: TBytes);
    procedure SetString(const Value: string);
  public
    property Name : string read GetString write SetString;
    property ID : TBytes read GetID write SetId;

    constructor Create;
    constructor CreateByRef( tpl : Pfido_bio_template_t );
    destructor Destroy; override;
  end;
  TFidoBiometricTemplateArr = TObjectList<TFidoBiometricTemplate>;

type
  TFidoBiometricDevice = class;
  TFidoBiometricTplArray = class(TObject)
  private
    fArrObj : TFidoBiometricTemplateArr;
    fTplArr : Pfido_bio_template_array_t;

    procedure Clear;
    procedure Init;
    function GetCount: integer;
    function GetItem(index: integer): TFidoBiometricTemplate;
  public
    property Count : integer read GetCount;
    property Items[ index : integer ] : TFidoBiometricTemplate read GetItem;

    procedure InitFromDev( dev : TFidoBiometricDevice; pin : string );

    constructor Create;
    destructor Destroy; override;
  end;

  TFidoBiometricEnroll = class(TObject)
  private
    fEnroll : Pfido_bio_enroll_t;
  public
    function LastStatus : byte;
    function RemainingSamples : byte;

    constructor Create;
    destructor Destroy; override;
  end;

  TFidoBiometricInfo = class(TObject)
  private
    fInfo : Pfido_bio_info_t;
  public
    function MaxSamples : byte;
    function DevType : byte;

    constructor Create;
    destructor Destroy; override;
  end;

  TFidoBiometricDevice = class(TFidoDevice)
  private
    fEnroll : TFidoBiometricEnroll;
    fInfo : TFidoBiometricInfo;
  public
    function TemplateArr( pin : string ) : TFidoBiometricTplArray;

    function GetInfo : TFidoBiometricInfo;

    function EnrollBegin(pin : string; template : TFidoBiometricTemplate; timeout : UInt32) : TFidoBiometricEnroll;
    procedure EnrollContinue( template : TFidoBiometricTemplate; timeout : UInt32 );
    procedure EnrollCancel;
    procedure EnrollRemove( template : TFidoBiometricTemplate; pin : string );

    destructor Destroy; override;
  end;

// ###################################################
// #### Credential api
// ###################################################
type
  TFidoCredentialType = (ctCOSEES256 = COSE_ES256, ctCoseEDDSA = COSE_EDDSA, ctCoseES384 = COSE_ES384, ctCoseRS256 = COSE_RS256);
  TFidoCredentialFmt = (fmDef, fmFido2, fmU2F);

  TBaseFido2Credentials = class(TObject)
  private
    function GetCredID: TBytes;
    function GetAAGuid: TBytes;
    function GetCredSigCount: Integer;
    procedure SetLargeBlobFlag(const Value: boolean);
    procedure SetID(const Value: string);
    procedure SetClientData(const Value: string);
    function GetMinPinLen: integer;
    procedure SetMinPinLen(const Value: integer);
  protected
    fCred : Pfido_cred_t;
    fCredType : TFidoCredentialType;

    fRelyingParty : string;
    fRelyingPartyName : string;
    fClientDataHash : TFidoSHA256Hash;      // client data hash
    fEnableHMACSecret : boolean;
    fHMACSecret: UTF8String;
    fResidentKey : fido_opt_t;              // create a resident key on the device
    fUserIdentification : fido_opt_t;
    fLargeBlockKeyFlag : boolean;
    fSmallBlob : TBytes;
    fMinPinLen : integer;

    // user identification
    fUserName, fDisplaNamy : string;
    fUserIcon : TBytes;
    fUserId : TBytes;

    // client
    fID: string;
    fClientData : string;

    fFmt : TFidoCredentialFmt;
    fsFmt : UTF8String;

    procedure UpdateCredentials; virtual;

    procedure InitCred;
    procedure FreeCred;

    procedure PrepareCredentials;

    procedure SetCredType(const Value: TFidoCredentialType);
    procedure SetDisplayName(const Value: string);
    procedure SetHMACSecret(const Value: boolean);
    procedure SetRelParty(const Value: string);
    procedure SetRelPartyName(const Value: string);
    procedure SetResidentKey(const Value: fido_opt_t);
    procedure SetUserIdent(const Value: fido_opt_t);
    procedure SetUserName(const Value: string);
    procedure SetFmt(const Value: TFidoCredentialFmt);
    procedure SetClientDataHash( cid : TFidoSHA256Hash );
  public
    property CredID : TBytes read GetCredID;
    property CredentialType : TFidoCredentialType read fCredType write SetCredType;
    property RelyingPartyName : string read fRelyingPartyName write SetRelPartyName;
    property RelyingParty : string read fRelyingParty write SetRelParty;
    property HMACSecretEnabled : boolean read fEnableHMACSecret write SetHMACSecret;
    property LargeBlobEnabled : boolean read fLargeBlockKeyFlag write SetLargeBlobFlag;
    property ResidentKey : fido_opt_t read fResidentKey write SetResidentKey;
    property UserIdentification : fido_opt_t read fUserIdentification write SetUserIdent;
    property UserName : string read fUserName write SetUserName;
    property UserDisplayName : string read fDisplaNamy write SetDisplayName;
    property Fmt : TFidoCredentialFmt read fFmt write SetFmt;
    property ClientDataHash : TFidoSHA256Hash read fClientDataHash write SetClientDataHash;
    property ID : string read fID write SetID;
    property ClientData : string read fClientData write SetClientData;
    property SigCount : Integer read GetCredSigCount;
    property MinPinLen : integer read GetMinPinLen write SetMinPinLen;

    property AAGuid : TBytes read GetAAGuid;

    procedure CreateRandomUid( len : integer );
    procedure SetUserId( uid : TBytes );
    procedure SetLargeBlockKeyFlag( value : boolean );
    procedure SetSmallBlob( data : TBytes );

    procedure SavePKToStream( stream : TStream );
    procedure SavePKToFile( fn : String );
    procedure SaveUIDToStream( stream : TStream );
    procedure SaveUIDToFile( fn : string);
    procedure SaveCredIDToStream( stream : TStream );
    procedure SaveCredIDToFile( fn : string );
    procedure SaveSigToFile( fn : string );
    procedure SaveSigToStream( stream : TStream );
    procedure SaveX5cToFile( fn : string );
    procedure SaveX5cToStream( stream : TStream );
    procedure SaveBlob( fn : string );
    procedure SaveBlobToStream( stream : TStream );


    // converts the webauthn object described here https://www.w3.org/TR/webauthn/#authenticator-data
    // -> basically converts to a raw cbor encoded bytes string
    class function WebAuthNObjDataToAuthData( webAuthnauthData : TBytes ) : TBytes;

    constructor Create;
    destructor Destroy; override;
  end;

  // creation of a credential on a key
  TFidoCredCreate = class(TBaseFido2Credentials)
  public
    procedure AddExcludeCred( cred : TBaseFido2Credentials );

    function CreateCredentials( dev : TFidoDevice; pin : string ) : boolean;
    function CreateCredentialsAndVerify( dev : TFidoDevice; pin : string ) : boolean;
  end;

  // verifcation api for credentials -> after verify the public key can be extracted
  TFidoCredVerify = class(TBaseFido2Credentials)
  private
    fAuthData : TBytes;
    fx509 : TBytes;
    fSig : TBytes;
  protected
    procedure UpdateCredentials; override;
  public
    function Verify( ClientDataHash : TFidoSHA256Hash ) : boolean;

    // extract the large blob data (2.1 feature)
    function LargeBlobKey : TBytes;

    // copies the verification data from already generated credentials (e.g. CreateCredentials)
    constructor Create( fromCred : TBaseFido2Credentials); overload;

    // data from external sources
    constructor Create( typ: TFidoCredentialType; fmt: TFidoCredentialFmt;
                        aRelyingPartyID, aRelyingPartyName : string;
                        authData : TBytes;
                        x509 : TBytes; Sig : TBytes; rk, uv : boolean;
                        ext : integer; smallBlob : TBytes); overload;
    destructor Destroy; override;
  end;

// ######################################################
// #### Assertion objects
// ######################################################
  TBaseFidoAssert = class(TObject)
  private
    fErr : string;

    fAssert : Pfido_assert_t;
    fAssertType : TFidoCredentialType;

    fRelyingParty : string;
    fHMACSecret : UTF8String;
    fClientHash : TFidoChallenge;       // challange
    fClientData : string;
    fEnableHMACSecret : boolean;
    fUserPresence : fido_opt_t;
    fUserVerification : fido_opt_t;     //

    // user identification
    fFmt : TFidoCredentialFmt;

    procedure PrepareAssert;
    procedure SetAssertType(const Value: TFidoCredentialType); virtual;
    procedure SetFmt(const Value: TFidoCredentialFmt);
    procedure SetHMACSecret(const Value: boolean);
    procedure SetRelParty(const Value: string);
    procedure SetUserIdent(const Value: fido_opt_t);
    procedure SetUserPresence(const Value: fido_opt_t);
    procedure SetHMACSecretValue(const Value: UTF8String);
    procedure SetClientData(const Value: string);
  protected
    procedure InitAssert;
    procedure FreeAssert;

    procedure UpdateAssert; virtual;
  public
    property ErrorMsg : string read fErr;
    property AssertType : TFidoCredentialType read fAssertType write SetAssertType;
    property RelyingParty : string read fRelyingParty write SetRelParty;
    property HMACSecretEnabled : boolean read fEnableHMACSecret write SetHMACSecret;
    property HMACSecret : UTF8String read fHMACSecret write SetHMACSecretValue;
    property UserVerification : fido_opt_t read fUserVerification write SetUserIdent;
    property Fmt : TFidoCredentialFmt read fFmt write SetFmt;
    property UserPresence : fido_opt_t read fUserPresence write SetUserPresence;
    property ClientDataHash : TFidoChallenge read fClientHash write fClientHash;
    property ClientData : string read fClientData write SetClientData;
    procedure CreateRandomCID;

    constructor Create;
    destructor Destroy; override;
  end;

// client side that performs the assertion on the key
  TFidoAssert = class(TBaseFidoAssert)
  private
    fHMacSalt : TBytes;
    fExtensions: integer;
    function GetAuthData( idx : integer ): TBytes;
    function GetSig( idx : integer ): TBytes;
    function GetHMAC(idx: integer): TBytes;
    function GetLargeBlob( idx : integer ): TBytes;
    function GetSmallBlob( idx : integer ): TBytes;
  public
    property AuthData[ idx : integer] : TBytes read GetAuthData;
    property Sig[ idx : integer ] : TBytes read GetSig;
    property HMACSecret[ idx : integer ] : TBytes read GetHMAC;
    property LargeBlob[ idx : Integer ] : TBytes read GetLargeBlob;
    property Blob[ idx : integer ] : TBytes read GetSmallBlob;
    property Extensions : integer read fExtensions;

    procedure AddAllowedCredential( cred : TBaseFido2Credentials );
    procedure SetHMACSecretSalt( salt : TBytes );

    function Perform( dev : TFidoDevice; sPin : string; var cnt : integer ) : boolean;
  end;

  // verification e.g. on the server
  TFidoAssertVerify = class(TBaseFidoAssert)
  private
    fPK : TBytes;
    fpk1 : Pes256_pk_t;
    fpk2 : Peddsa_pk_t;
    fpk3 : Prs256_pk_t;
    fPK4 : Pes384_pk_t;

    procedure SetAssertType(const Value: TFidoCredentialType); override;
    procedure InitPublikKey;
    procedure ClearPK;
    function GetKeyPtr : Pointer;
    procedure SetPK(const Value: TBytes);
  public
    property PK : TBytes read fPK write SetPK;

    procedure LoadPKFromStream( stream : TStream );
    procedure LoadPKFromFile( fn : string );

    function Verify( authData : TBytes; sig : TBytes; ext : integer = 0 ) : boolean;

    constructor Create;
    destructor Destroy; override;
  end;

// ####################################################
// #### credential management
// note this api is only available on Yubikey since Firmware > 5.2
// creation of this object will raise an invalid command error
type
  TFido2RelayParty = class(TObject)
  private
    fIdx : integer;
    fID : string;
    fName : string;
    fHash : TBytes;
  public
    property Idx : integer read fIdx;
    property ID : String read fID;
    property Name : string read fName;
    property Hash : TBytes read fHash;

    constructor Create( rp : Pfido_credman_rp_t; idx : size_t );
    destructor Destroy; override;
  end;
  TFido2Credential = class(TBaseFido2Credentials)
  private
    fAuthData : TBytes;
    fx509 : TBytes;
    fSig : TBytes;
    fCredId : TBytes;
    // fCredGuid : TBytes;
  public
    constructor Create( cred : Pfido_cred_t );
  end;

  TFido2ResidentKey = class(TObject)
  private
    fCount : integer;
    fCredList : Array of TFido2Credential;
    function GetCred(idx: integer): TFido2Credential;
  public
    property Count : integer read fCount;
    property Cred[idx : integer] : TFido2Credential read GetCred;

    constructor Create( rk : Pfido_credman_rk_t );
    destructor Destroy; override;
  end;
type
  TFido2RelayPartyList = TObjectList<TFido2RelayParty>;
  TFido2ResidentKeyList = TObjectList<TFido2ResidentKey>;
  TFido2CredentialManager = class(TObject)
  private
    fMetaCredMan : Pfido_credman_metadata_t;
    fCredManRP : Pfido_credman_rp_t;
    fNumResidentKeys : int64;
    fNumResidentKeysRemain : int64;
    fRelayPartyList : TFido2RelayPartyList;
    fResidentKeyList : TFido2ResidentKeyList;

    procedure ReadDev;
    procedure ReadRelayingParties;

    procedure Clear;
  public
    property NumResidentKeys : int64 read fNumResidentKeys;
    property NumResidentKeysRemain : int64 read fNumResidentKeysRemain;

    property RelayPartys : TFido2RelayPartyList read fRelayPartyList;
    property ResidentKeys : TFido2ResidentKeyList read fResidentKeyList;

    procedure DelResidentKey( dev : TFidoDevice; credId : TBytes; pin : string );

    // returns fals if no credential management is avail
    function Open(dev : TFidoDevice; pin : string; var ErrMsg : string) : boolean;

    constructor Create;
    destructor Destroy; override;
  end;


// to get results from the logger initialize the Fido with the debug flag
// -> fido_init(cFidoInitDebug);
procedure InitFidoLogger( OnLog : TFidoLogMsg );

implementation

// ###########################################
// #### Fido logging
// ###########################################

var loc_fidoLog : TFidoLogMsg;

procedure FidoLog(msg : PAnsiChar); cdecl;
begin
     if Assigned(loc_fidoLog) then
        loc_fidoLog( String( UTF8String( msg ) ) );
end;

procedure InitFidoLogger( OnLog : TFidoLogMsg );
begin
     loc_fidoLog := OnLog;
     fido_set_log_handler(FidoLog);
end;

// #########################################################
// #### helper functions
// #########################################################

const cMaxFido2Len = 63;

procedure RandomInit(var blk; len : integer; ensureNonZeroFirstByte : boolean);
var i : integer;
    pBlk : PByteArray;
begin
     pBlk := @blk;

     pBlk^[0] := 0;

     // first byte may not be 0 or one (at least as for the user id)
     repeat
           pBlk^[0] := Byte( Random(High(Byte) + 1) );
     until (ensureNonZeroFirstByte = False) or (pBlk^[0] > 1);

     for i := 1 to len - 1 do
         pBlk^[i] := Byte( Random(High(Byte) + 1) );
end;

function ptrToStr( ps : PAnsiChar ) : string;
begin
     Result := '';
     if Assigned(ps) then
        Result := string(ps);
end;
function ptrToByteArr( pb : PByte; len : integer ) : TBytes;
begin
     SetLength(Result, len);
     if len > 0 then
        Move( pb^, Result[0], len );
end;

procedure CR( aErrCode : integer );
begin
     if aErrCode <> FIDO_OK then
        raise EFidoException.Create(aErrCode);
end;

// #########################################################
// ####
// #########################################################


{ TFido2Dev }

// #########################################################
// #### Fido Device
// #########################################################

procedure TFidoDevice.ReadProperties(di: Pfido_dev_info_t);
begin
     fManufactStr := String( fido_dev_info_manufacturer_string( di ));
     fProductInfo := String( fido_dev_info_product_string( di ));
     fVendor := fido_dev_info_vendor( di );
     fProduct := fido_dev_info_product(di);
end;

class function TFidoDevice.DevList: TFidoDevList;
const cNumMaxDev : integer = 64;
var numFound : integer;
    i : integer;
    di : Pfido_dev_info_t;
    aList : Pfido_dev_info_t;
    dev : TFidoDevice;
begin
     Result := TFidoDevList.Create( False );

     aList := fido_dev_info_new( cNumMaxDev );
     if aList = nil then
        raise EFidoAllocException.Create('No list allocated');

     try
        numFound := 0;
        CR(fido_dev_info_manifest( aList, cNumMaxDev, numFound ));

        for i := 0 to numFound - 1 do
        begin
             di := fido_dev_info_ptr(aList, i);

             assert(Assigned(di), 'Device pointer missing...');

             dev := TFidoDevice.CreateFromDevInfo( di );
             Result.Add(dev);
        end;
     finally
            fido_dev_info_free( @aList, cNumMaxDev );
     end;
end;

destructor TFidoDevice.Destroy;
begin
     CloseDevice;
     fCbor.Free;

     inherited;
end;

constructor TFidoDevice.CreateFromPath(usbPath: String);
begin
     fUSBPath := UTF8String(usbPath);
     OpenDevice;

     inherited Create;
end;

constructor TFidoDevice.CreateFromDevInfo(di: Pfido_dev_info_t);
begin
     fUSBPath := UTF8String( fido_dev_info_path(di) );
     ReadProperties(di);
     ReadDev;

     inherited Create;
end;

procedure TFidoDevice.OpenDevice;
var r : integer;
begin
     if not Assigned(fDev) then
     begin
          fDev := fido_dev_new;
          assert( Assigned(fDev), 'Error allocating memory for device');

          r := fido_dev_open(fDev, PAnsiChar( fUSBPath ) );

          if r <> FIDO_OK then
          begin
               fido_dev_free(fDev);
               CR(r);
          end;
     end;
end;

procedure TFidoDevice.ReadDev;
var flags : byte;
begin
     OpenDevice;
     fProtocol := fido_dev_protocol(fDev);
     fDevMajor := fido_dev_major(fDev);
     fDevMinor := fido_dev_minor(fDev);
     fDevBuild := fido_dev_build(fDev);
     flags := fido_dev_flags(fDev);
     fHasUserVerification := fido_dev_has_uv( fDev );

     if fido_dev_get_retry_count(fDev, fRetryCnt) <> FIDO_OK then
        fRetryCnt := -1;
     if fido_dev_get_uv_retry_count(fDev, fUVRetryCnt) <> FIDO_OK then
        fUVRetryCnt := -1;  // set to -1 in case it is not defined

     fDevFlags := [];
     if flags and FIDO_CAP_WINK <> 0 then
        include(fDevFlags, dfWink);
     if flags and FIDO_CAP_CBOR <> 0 then
        include(fDevFlags, dfCBOR);
     if (flags and FIDO_CAP_NMSG) = 0 then
        include(fDevFlags, dfMsg);

     fIsFido2 := fido_dev_is_fido2( fdev );
     fIsWinHello := fido_dev_is_winhello( fdev );

     fSupportPin := fido_dev_supports_pin( fDev );
     fSupportCredProtection := fido_dev_supports_cred_prot( fDev );
     fSupportCredManager := fido_dev_supports_credman( fDev );
     fSupportUserVerification := fido_dev_supports_uv( fDev );
     fSupportPermissions := fido_dev_supports_permissions( fDev );

     fCBOR := nil;
     fHasBlobSupport := False;

     if fIsFido2 then
     begin
          fCbor := TFido2CBOR.Create( fDev );
          // as per mail with pedro martelletto
          fHasBlobSupport := fCbor.Extensions.IndexOf('credBlob') >= 0 ;  // ?!? better check for "largeBlobs" options as stated in fido 2.1 client to authenticator protocol
     end;
end;

procedure TFidoDevice.SetLargeBlob(key, data: TBytes; pin: string);
var ansiPin : Utf8String;
begin
     assert( Assigned( fDev ), 'Error no device opened');
     assert( (Length(key) > 0) and (length(data) > 0), 'Error no data');
     if not fHasBlobSupport then
        raise EFidoPropertyException.Create('Error: blobs not supported by this device');

     ansiPin := UTF8String( pin );
     CR( fido_dev_largeblob_set( fDev, @key[0], Length(key), @data[0], Length(data), PAnsiChar( ansiPin ) ) );
end;

procedure TFidoDevice.SetLargeBlobArr(cborData: TCborItem; pin: string);
var data : TMemoryStream;
    ansiPin : Utf8String;
begin
     assert( Assigned( fDev ), 'Error no device opened' );
     assert( Assigned( cborData ), 'Error no cbor item' );
     if not fHasBlobSupport then
        raise EFidoPropertyException.Create('Error: blobs not supported by this device');

     data := TMemoryStream.Create;
     try
        cborData.CBOREncode(data);
        ansiPin := UTF8String( pin );

        CR( fido_dev_largeblob_set_array( fDev, data.Memory, data.Size, PAnsiChar(ansiPin) ) );
     finally
            data.Free;
     end;
end;

procedure TFidoDevice.SetLargeBlobArr(data: TBytes; pin: string);
var ansiPin : Utf8String;
begin
     assert( Assigned( fDev ), 'Error no device opened');
     assert( (length(data) > 0), 'Error no data');

     if not fHasBlobSupport then
        raise EFidoPropertyException.Create('Error: blobs not supported by this device');

     ansiPin := UTF8String( pin );
     CR( fido_dev_largeblob_set_array( fDev, @data[0], Length(data), PAnsiChar( ansiPin ) ) );
end;

function TFidoDevice.SetPin(oldPin, newPin: string; var ErrStr : string): boolean;
var r : integer;
    newPinUtf8 : utf8string;
begin
     newPinUTF8 := UTF8String( newPin );
     if (Length(newPinUtf8) < 4) or (LengtH(newPinUtf8) > 255) then
     begin
          ErrStr := '4 <= pin length <= 255';
          exit(False);
     end;
     OpenDevice;

     errStr := '';

     r := fido_dev_set_pin( fDev, PAnsiChar( ansiString(newPin) ), PAnsiChar( AnsiString(oldPin) ) );
     Result := r = FIDO_OK;
     if not Result then
        errStr := String( fido_strerr( r ) );
end;

procedure TFidoDevice.SetTimeout(ms: integer);
begin
     assert( Assigned( fDev ), 'Error no device opened');
     CR( fido_dev_set_timeout( fDev, ms ) );
end;

// To reset start this routine within 5 seconds after attaching the device!
procedure TFidoDevice.Reset;
begin
     OpenDevice;
     CR(fido_dev_reset( fDev ));
     CloseDevice;
end;

procedure TFidoDevice.BeginTouch;
begin
     assert( Assigned( fDev ), 'Error no device opened');

     CR( fido_dev_get_touch_begin( fDev ) );
end;

procedure TFidoDevice.Cancel;
begin
     assert( Assigned( fDev ), 'Error no device opened');

     CR( fido_dev_cancel( fDev ) );
end;

procedure TFidoDevice.CloseDevice;
begin
     if Assigned(fDev) then
     begin
          fido_dev_close(fDev);
          fido_dev_free(fDev);
     end;

     fDev := nil;
end;

{ EFido2Exception }

constructor EFidoException.Create(aErrCode: integer);
var pMsg : PAnsiChar;
begin
     pMsg := fido_strerr( aErrCode );

     inherited Create( String( pMsg ) );
end;

{ TFido2CBOR }

constructor TFido2CBOR.Create(dev: PFido_dev_t);
begin
     fCBORVersions := TStringList.Create;
     fCBORExtension := TStringList.Create;
     fCBORTransports := TStringList.Create;
     fCBORCertNames := TStringList.Create;

     if dev <> nil then
        ReadProperties(dev);

     inherited Create;
end;

procedure TFido2CBOR.ReadProperties(dev: PFido_dev_t);
var ci : Pfido_cbor_info_t;
    infoLen : integer;
    pInfo : PPAnsiChar;
    i : integer;
    pBGuid : PByte;
    valuePtr : PBoolean;
    pinProto : PByte;
    pinProtoLen : integer;
    pTransp : PPAnsiChar;
    transpLen : integer;
    algoCount : integer;
begin
     ci := fido_cbor_info_new;
     if ci = nil then
        raise EFidoAllocException.Create('Error cannot create cbor info');
     try
        CR( fido_dev_get_cbor_info( dev, ci ) );

        infoLen := fido_cbor_info_versions_len( ci );
        pinfo := fido_cbor_info_versions_ptr( ci );

        for i := 0 to infoLen - 1 do
        begin
             fCBORVersions.Add( String( pInfo^ ) );
             inc(pInfo);
        end;

        infoLen := fido_cbor_info_extensions_len( ci );
        pInfo := fido_cbor_info_extensions_ptr( ci );
        for i := 0 to infoLen - 1 do
        begin
             fCBORExtension.Add( String( pinfo^ ) );
             inc(pInfo);
        end;

        infoLen := fido_cbor_info_certs_len( ci );
        pInfo := fido_cbor_info_certs_name_ptr( ci );
        for i := 0 to infoLen - 1 do
        begin
             fCBORCertNames.Add( String( pinfo^ ) );
             inc(pInfo);
        end;

        pBGuid := fido_cbor_info_aaguid_ptr(ci);
        infoLen := fido_cbor_info_aaguid_len( ci );

        SetLength( fCBORUUID, infoLen );
        if infoLen > 0 then
           move( pBGuid^, fCBORUUID[0], infoLen);

        if infoLen = 16 then
           fCBORGuid := GUIDToString( PGUID( pBGuid )^ );


        pInfo := fido_cbor_info_options_name_ptr(ci);
        infoLen := fido_cbor_info_options_len(ci);
        valuePtr := fido_cbor_info_options_value_ptr(ci);

        pTransp := fido_cbor_info_transports_ptr(ci);
        transpLen := fido_cbor_info_transports_len(ci);

        SetLength( fCBOROptions, infoLen );

        assert(pInfo <> nil, 'No options name ptr avail');
        assert(valuePtr <> nil, 'No option array avail');

        for i := 0 to infoLen - 1 do
        begin
             fCBOROptions[i] := TFido2CBOROption.Create( String(pInfo^), valuePtr^ );
             inc(pInfo);
             inc(valuePtr);
        end;

        for i := 0 to transpLen - 1 do
        begin
             fCBORTransports.Add( String(pTransp^) );
             inc(pTransp);
        end;

        algoCount := fido_cbor_info_algorithm_count(ci);
        SetLength(fCBORCose, algoCount);
        for i := 0 to algoCount - 1 do
            fCBORCose[i] := fido_cbor_info_algorithm_cose(ci, i);

        fCBORmaxMsgSize := fido_cbor_info_maxmsgsiz( ci );
        fCBORmaxLargeBlob := fido_cbor_info_maxlargeblob( ci );

        pinProto := fido_cbor_info_protocols_ptr( ci );
        pinProtoLen := fido_cbor_info_protocols_len(ci);
        SetLength( fCBORPinProtocols, pinProtoLen);
        if pinProtoLen > 0 then
           Move( pinProto^, fCBORPinProtocols[0], pinProtoLen);


        fCBORMaxCredCntLst := fido_cbor_info_maxcredcntlst(ci);
        fCBORMaxCredidlen := fido_cbor_info_maxcredidlen(ci);
        fCBORMaxBlobLen := fido_cbor_info_maxcredbloblen(ci);
        fCBORFWVersion := fido_cbor_info_fwversion(ci);

        fCBORMaxrpidMinpinlen := fido_cbor_info_maxrpid_minpinlen(ci);
        fCBORMinPinLen := fido_cbor_info_minpinlen(ci);
        fCBORUVAttempts := fido_cbor_info_uv_attempts(ci);
        fCBORUVMOdality := fido_cbor_info_uv_modality(ci);
        fCBORRKRemaining := fido_cbor_info_rk_remaining(ci);
        fCBORNewPinRequired := fido_cbor_info_new_pin_required(ci);
     finally
            fido_cbor_info_free(ci);
     end;
end;

destructor TFido2CBOR.Destroy;
var i: Integer;
begin
     fCBORVersions.Free;
     fCBORExtension.Free;
     fCBORTransports.Free;
     fCBORCertNames.Free;

     for i := 0 to Length(fCBOROptions) - 1 do
         fCBOROptions[i].Free;
     fCBOROptions := nil;

     inherited;
end;

function TFido2CBOR.UUIDToGuid: String;
begin
     Result := '';
     if Length(fCBORUUID) = sizeof(TGuid) then
        Result := GUIDToString( PGuid( @fCBORUUID[0])^ );
end;

function TFido2CBOR.GetCertName(index: Integer): string;
begin

end;

function TFido2CBOR.GetCertNameLen: integer;
begin
     Result := fCBORCertNames.Count;
end;

function TFido2CBOR.GetCoseAlgorithm(index: integer): integer;
begin
     Result := fCBORCose[index];
end;

function TFido2CBOR.GetCoseAlgorithmCnt: integer;
begin
     Result := Length(fCBORCose);
end;

function TFido2CBOR.GetOption(index: integer): TFido2CBOROption;
begin
     assert( (index >= 0) and (index < Length(fCborOptions)), 'Index out of bounds');

     Result := fCBOROptions[index];
end;

function TFido2CBOR.GetOptionsCnt: integer;
begin
     Result := Length(fCBOROptions);
end;

{ TFido2CBOROption }

constructor TFido2CBOROption.Create(aName: string; aVal : boolean);
begin
     fName := aName;
     fValue := aVal;

     inherited Create;
end;

{ TFido2Credentials }

constructor TBaseFido2Credentials.Create;
begin
     inherited Create;

     fRelyingParty := 'localhost';
     fRelyingPartyName := 'Home sweet home';
     fUserIcon := nil;

     fUserName := 'anonymous';
     fDisplaNamy := 'anonymous';
     fEnableHMACSecret := False;

     // init initial userid and client challange data blocks
     RandomInit( fClientDataHash, sizeof(fClientDataHash), False );
     fCredType := ctCOSEES256;

     fResidentKey := FIDO_OPT_OMIT;
     fUserIdentification := FIDO_OPT_OMIT;
     fFmt := fmDef;

     inherited Create;
end;

procedure TBaseFido2Credentials.UpdateCredentials;
var pIcon : PByte;
    ext : integer;
    s : UTF8String;
begin
     if not Assigned(fCred) then
        exit;

     // type
     CR(fido_cred_set_type( fcred, Integer( fcredType ) ) );
     CR(fido_cred_set_clientdata_hash( fcred, @fClientDataHash[0], Length(fClientDataHash)));

     // relying party
     CR(fido_cred_set_rp(fcred, PAnsiChar( UTF8String( fRelyingParty ) ),
                         PAnsiChar( UTF8String(fRelyingPartyName )) ) );

     // user
     if Length(fUserId) > 0 then
     begin
          pIcon := nil;
          if Length(fUserIcon) > 0 then
             pIcon := @fUserIcon[0];

          CR( fido_cred_set_user(fcred, @fuserId[0], Length(fUserId),
                                 PAnsiChar( UTF8String( fUserName ) ),
                                 PAnsiChar( UTF8String( fDisplaNamy ) ),
                                 PAnsiChar( pIcon ) ) );
     end;

     // format
     case fFmt of
       fmFido2: CR( fido_cred_set_fmt( fCred, 'packed'));
       fmU2F:   CR( fido_cred_set_fmt( fCred, 'fido-u2f'));
     end;

     fSFmt := UTf8String(fido_cred_fmt(fCred));

     // set extension
     ext := 0;
     if fLargeBlockKeyFlag then
        ext := ext or FIDO_EXT_LARGEBLOB_KEY;
     if fEnableHMACSecret then
        ext := ext or FIDO_EXT_HMAC_SECRET;
     if Length(fSmallBlob) > 0 then
        ext := ext or FIDO_EXT_CRED_BLOB;

     CR( fido_cred_set_extensions( fcred,  ext ) );

     if Length(fSmallBlob) > 0 then
        CR( fido_cred_set_blob( fcred, @fSmallBlob[0], Length(fSmallBlob) ) );

     // id
     if fID <> '' then
     begin
          s := UTF8String( fID );
          CR( fido_cred_set_id( fcred, PAnsiChar(s), Length(s)));
     end;
     if fClientData <> '' then
     begin
          s := UTf8String( fClientData );
          CR( fido_cred_set_clientdata( fcred, PAnsiChar(s), Length(s)));
     end;

     if fMinPinLen > 0 then
        CR( fido_cred_set_pin_minlen( fcred, fMinPinLen ) );

     // resident key
     CR( fido_cred_set_rk( fcred, fResidentKey ) );
     CR( fido_cred_set_uv( fcred, fUserIdentification ) );
end;

class function TBaseFido2Credentials.WebAuthNObjDataToAuthData(
  webAuthnauthData: TBytes): TBytes;
var cborRawByteStr : TCborByteString;
    byteStr : RawByteString;
    memStream : TMemoryStream;
begin
     SetLength( byteStr, Length(webAuthnauthData));
     if byteStr <> '' then
        Move( webAuthnauthData[0], byteStr[1], Length(webAuthnauthData));

     cborRawByteStr := TCborByteString.Create( byteStr );
     memStream := TMemoryStream.Create;
     try
        cborRawByteStr.CBOREncode(memStream);

        SetLength(Result, memStream.Size);
        memStream.Position := 0;
        if Length(Result) <> 0 then
           Move( PByte(memStream.Memory)^, Result[0], Length(Result));
     finally
            cborRawByteStr.Free;
            memStream.Free;
     end;
end;

destructor TBaseFido2Credentials.Destroy;
begin
     FreeCred;

     inherited;
end;

procedure TBaseFido2Credentials.SetCredType(const Value: TFidoCredentialType);
begin
     fCredType := Value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetDisplayName(const Value: string);
begin
     fDisplaNamy := Value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetHMACSecret(const Value: boolean);
begin
     fEnableHMACSecret := Value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetID(const Value: string);
begin
     fID := Value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetLargeBlobFlag(const Value: boolean);
begin
     fLargeBlockKeyFlag := Value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetLargeBlockKeyFlag(value: boolean);
begin
     fLargeBlockKeyFlag := value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetMinPinLen(const Value: integer);
begin
     fMinPinLen := value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetRelParty(const Value: string);
begin
     fRelyingParty := Value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetRelPartyName(const Value: string);
begin
     fRelyingPartyName := Value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetResidentKey(const Value: fido_opt_t);
begin
     fResidentKey := Value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetSmallBlob(data: TBytes);
begin
     if Length(data) > cMaxSmallBlobLen then
        raise EFidoPropertyException.Create('Blob length exceeds maximum size of ' + IntToStr(cMaxSmallBlobLen));
     fSmallBlob := data;
     fResidentKey := FIDO_OPT_TRUE;

     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetUserIdent(const Value: fido_opt_t);
begin
     fUserIdentification := Value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetUserName(const Value: string);
begin
     fUserName := Value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.InitCred;
begin
     if not Assigned(fCred) then
     begin
          fCred := fido_cred_new;
          if not Assigned(fCred) then
             raise EFidoAllocException.Create('Failed to create credential structure');
     end;
end;

procedure TBaseFido2Credentials.SetUserId(uid: TBytes);
begin
     fUserId := Copy(uid, 0, Length(uid));
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetClientData(const Value: string);
begin
     fClientData := Value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetClientDataHash(cid: TFidoSHA256Hash);
begin
     fClientDataHash := cid;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.FreeCred;
begin
     if Assigned(fCred) then
        fido_cred_free(fCred);

     fCred := nil;
end;

function TBaseFido2Credentials.GetAAGuid: TBytes;
begin
     if fCred = nil then
        raise EFidoPropertyException.Create('No credentials');

     Result := ptrToByteArr(fido_cred_aaguid_ptr(fCred), fido_cred_aaguid_len(fCred) );
end;

function TBaseFido2Credentials.GetCredID: TBytes;
begin
     if fCred = nil then
        raise EFidoPropertyException.Create('No credentials');

     Result := ptrToByteArr(fido_cred_id_ptr(fCred), fido_cred_id_len(fCred));
end;

function TBaseFido2Credentials.GetCredSigCount: Integer;
begin
     Result := integer( fido_cred_sigcount( fCred ) );
end;

function TBaseFido2Credentials.GetMinPinLen: integer;
begin
     if fCred = nil then
        raise EFidoPropertyException.Create('No credentials');

     Result := fido_cred_pin_minlen( fCred );
end;

procedure TBaseFido2Credentials.PrepareCredentials;
begin
     InitCred;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.SetFmt(const Value: TFidoCredentialFmt);
begin
     fFmt := Value;
     UpdateCredentials;
end;

procedure TBaseFido2Credentials.CreateRandomUid(len: integer);
begin
     SetLength(fUserId, len);
     RandomInit(fUserId[0], len, True);
end;

procedure TBaseFido2Credentials.SavePKToStream(stream: TStream);
var pkLen : LongInt;
begin
     if fCred = nil then
        raise EFidoPropertyException.Create('No credentials');

     pkLen := fido_cred_pubkey_len( fcred );
     stream.WriteBuffer( pkLen, sizeof(pkLen));
     if pkLen > 0 then
        stream.WriteBuffer( fido_cred_pubkey_ptr( fcred )^, pkLen );
end;

procedure TBaseFido2Credentials.SaveSigToFile(fn: string);
var fs : TFileStream;
begin
     fs := TFileStream.Create( fn, fmCreate );
     try
        SaveSigToStream(fs);
     finally
            fs.Free;
     end;
end;

procedure TBaseFido2Credentials.SaveSigToStream(stream: TStream);
var sigLen : LongInt;
begin
     if fCred = nil then
        raise EFidoPropertyException.Create('No credentials');

     sigLen := fido_cred_sig_len( fcred );
     stream.WriteBuffer( sigLen, sizeof(sigLen));
     if sigLen > 0 then
        stream.WriteBuffer( fido_cred_sig_ptr( fcred )^, sigLen );
end;

procedure TBaseFido2Credentials.SaveUIDToStream(stream: TStream);
var idLen : LongInt;
begin
     if fCred = nil then
        raise EFidoPropertyException.Create('No credentials');

     idLen := Length(fUserId);
     stream.WriteBuffer( idLen, sizeof(idLen));
     if idLen > 0 then
        stream.WriteBuffer( fUserId[0], idLen );
end;

procedure TBaseFido2Credentials.SaveX5cToFile(fn: string);
var fs : TFileStream;
begin
     fs := TFileStream.Create( fn, fmCreate );
     try
        SaveX5cToStream(fs);
     finally
            fs.Free;
     end;
end;

procedure TBaseFido2Credentials.SaveX5cToStream(stream: TStream);
var x5CLen : LongInt;
begin
     if fCred = nil then
        raise EFidoPropertyException.Create('No credentials');

     x5CLen := fido_cred_x5c_len( fcred );
     stream.WriteBuffer( x5CLen, sizeof(x5CLen));
     if x5CLen > 0 then
        stream.WriteBuffer( fido_cred_x5C_ptr( fcred )^, x5CLen );
end;

procedure TBaseFido2Credentials.SaveCredIDToStream(stream: TStream);
var idLen : integer;
    pData : PByte;
begin
     if fCred = nil then
        raise EFidoPropertyException.Create('No credentials');

     idLen := fido_cred_id_len( fCred );
     pData := fido_cred_id_ptr( fCred );
     stream.WriteBuffer( idLen, sizeof(idLen));
     if (idLen > 0) and (pData <> nil) then
        stream.WriteBuffer( pData^, idLen );
end;

procedure TBaseFido2Credentials.SaveBlob(fn: string);
var fs : TFileStream;
begin
     if fCred = nil then
        raise EFidoPropertyException.Create('No credentials');

     if not fLargeBlockKeyFlag then
        raise EFidoPropertyException.Create('Large blob flag not set - cannot save');

     fs := TFileStream.Create( fn, fmCreate );
     try
        SaveBlobToStream( fs );
     finally
            fs.Free;
     end;
end;

procedure TBaseFido2Credentials.SaveBlobToStream(stream: TStream);
var blobLen : integer;
    pBlob : PByte;
begin
     if fCred = nil then
        raise EFidoPropertyException.Create('No credentials');

     if not fLargeBlockKeyFlag then
        raise EFidoPropertyException.Create('Large blob flag not set - cannot save');

     blobLen := fido_cred_largeblob_key_len( fCred );
     pBlob := fido_cred_largeblob_key_ptr( fCred );

     if (blobLen > 0) and (pBlob <> nil) then
        stream.WriteBuffer(pBlob^, blobLen);
end;

// #########################################################
// ####
// #########################################################

{ TFidoCredVerify }

// #########################################################
// #### Credential Verification
// #########################################################

procedure TFidoCredVerify.UpdateCredentials;
begin
     inherited;

     // authdata
     if Length(fAuthData) > 0 then
        CR( fido_cred_set_authdata( fcred, @fAuthData[0], Length(fAuthData) ) );

     if Length(fx509) > 0 then
        CR( fido_cred_set_x509( fcred, @fx509[0], Length(fx509) ) );
     if Length(fSig) > 0 then
        CR( fido_cred_set_sig( fcred, @fSig[0], Length(fSig) ) );
end;

function TFidoCredVerify.Verify(ClientDataHash: TFidoSHA256Hash): boolean;
var r : integer;
begin
     if Length(fAuthData) = 0 then
        raise EFidoPropertyException.Create('authdata missing');
     if Length(fx509) = 0 then
        raise EFidoPropertyException.Create('x509 missing');
     if Length(fSig) = 0 then
        raise EFidoPropertyException.Create('sig missing');

     fClientDataHash := ClientDataHash;
     PrepareCredentials;

     // ###########################################
     // #### Verification
     r := fido_cred_verify( fcred );
     Result := r = FIDO_OK;
     if r <> FIDO_OK then
     begin
          Result := False;

          if r <> FIDO_ERR_INVALID_CREDENTIAL then
             CR(r);
     end;
end;

constructor TFidoCredVerify.Create(typ: TFidoCredentialType; fmt: TFidoCredentialFmt;
  aRelyingPartyID, aRelyingPartyName : string;
  authData, x509, Sig: TBytes;
  rk, uv: boolean; ext: integer; smallBlob : TBytes);
begin
     inherited Create;

     fRelyingParty := aRelyingPartyID;
     fRelyingPartyName := aRelyingPartyName;
     fCredType := typ;
     fFmt := fmt;
     fAuthData := Copy(authData, 0, Length(authData));
     fx509 := Copy(x509, 0, Length(x509));
     fSig := Copy(Sig, 0, Length(Sig));
     if rk
     then
         fResidentKey := FIDO_OPT_TRUE
     else
         fResidentKey := FIDO_OPT_FALSE;
     if uv
     then
         fUserIdentification := FIDO_OPT_TRUE
     else
         fUserIdentification := FIDO_OPT_FALSE;

     fEnableHMACSecret := (ext and FIDO_EXT_HMAC_SECRET) <> 0;
     fLargeBlockKeyFlag := (ext and FIDO_EXT_LARGEBLOB_KEY) <> 0;
     fSmallBlob := Copy( smallBlob, 0, Length(smallBlob) );
end;

constructor TFidoCredVerify.Create(fromCred: TBaseFido2Credentials);
begin
     assert( fromCred.fCred <> nil, 'No Credentials initialized');

     inherited Create;

     fCredType := fromCred.fCredType;
     fsFmt := UTF8String(fido_cred_fmt( fromCred.fCred ));
     fFmt := fmDef;
     if fsFmt = 'packed' then
        fFmt := fmFido2;
     if fsFmt = 'fido-u2f' then
        fFmt := fmU2f;

     fResidentKey := fromCred.fResidentKey;

     fRelyingParty := fromCred.fRelyingParty;
     fRelyingPartyName := fromCred.fRelyingPartyName;
     fEnableHMACSecret := fromCred.fEnableHMACSecret;
     fLargeBlockKeyFlag := fromCred.fLargeBlockKeyFlag;
     fSmallBlob := Copy(fromCred.fSmallBlob, 0, Length(fromCred.fSmallBlob));

     // authdata
     fAuthData := ptrToByteArr(fido_cred_authdata_ptr(fromCred.fCred), fido_cred_authdata_len(fromCred.fcred));

     // x509
     fx509 := ptrToByteArr(fido_cred_x5c_ptr(fromCred.fcred), fido_cred_x5c_len(fromCred.fcred) );

     // sig
     fSig := ptrToByteArr(fido_cred_sig_ptr(fromCred.fcred), fido_cred_sig_len(fromCred.fcred) );
end;

destructor TFidoCredVerify.Destroy;
begin
     inherited;
end;

function TFidoCredVerify.LargeBlobKey: TBytes;
begin
     Result := ptrToByteArr( fido_cred_largeblob_key_ptr(fCred), fido_cred_largeblob_key_len(fCred));
end;

// #########################################################
// ####
// #########################################################

{ TFidoCredCreate }

// #########################################################
// #### Credential Create
// #########################################################

function TFidoCredCreate.CreateCredentials(dev: TFidoDevice;
  pin: string): boolean;
var pPin : PAnsiChar;
    utf8Pin : UTF8String;
    r : integer;
begin
     if not dev.IsFido2 and (fFmt = fmFido2) then
        exit(False);

     PrepareCredentials;

     pPin := nil;
     if pin <> '' then
     begin
          utf8Pin := UTF8String(pin);
          pPin := PAnsiChar(utf8Pin);
     end;

     // create the credentials on the device
     r := fido_dev_make_cred( dev.DevHdl, fCred, pPin );

     Result := r = FIDO_OK;

     // only if a wrong pin is supplied the exception is raised
     if r <> FIDO_ERR_PIN_INVALID then
        CR(r);
end;

function TFidoCredCreate.CreateCredentialsAndVerify(dev: TFidoDevice;
  pin: string): boolean;
var credVerify : TFidoCredVerify;
begin
     Result := CreateCredentials(dev, pin);

     // just put it completely through the authentication pipe
     if Result then
     begin
          credVerify := TFidoCredVerify.Create(self);
          try
             Result := credVerify.Verify(fClientDataHash);
          finally
                 credVerify.Free;
          end;
     end;
end;

procedure TFidoCredCreate.AddExcludeCred(cred: TBaseFido2Credentials);
var idLen : integer;
begin
     PrepareCredentials;

     if cred.fCred = nil then
        cred.PrepareCredentials;

     idLen := fido_cred_id_len(cred.fCred);
     if idLen > 0 then
        CR( fido_cred_exclude(fCred, fido_cred_id_ptr(cred.fCred), idLen) );
end;

// ##################################################
// ####
// ##################################################

{ TFidoAssert }

// ##################################################
// #### Fido Assertion
// ##################################################

procedure TBaseFidoAssert.InitAssert;
begin
     if not Assigned(fAssert) then
     begin
          fAssert := fido_assert_new;
          if not Assigned(fAssert) then
             raise EFidoAllocException.Create('Error could not allocate memory for assert');
     end;
end;

procedure TBaseFidoAssert.FreeAssert;
begin
     if Assigned(fAssert) then
        fido_assert_free( fAssert );
     fAssert := nil;
end;

procedure TBaseFidoAssert.UpdateAssert;
var s : UTF8String;
    b : TBytes;
begin
     if not Assigned(fAssert) then
        exit;

     if fClientData <> '' then
     begin
          // clientdata hash will be calculated when set...
          s := UTF8String( fClientData );
          CR( fido_assert_set_clientdata(fAssert, PAnsiChar(s), Length(s)));
          b := ptrToByteArr( fido_assert_clientdata_hash_ptr(fAssert), fido_assert_clientdata_hash_len(fAssert) );
          if Length(b) = Length(fClientHash) then
             Move(b[0], fClientHash[0], Length(fClientHash));
     end
     else
         CR( fido_assert_set_clientdata_hash(fAssert, @fClientHash[0], length(fClientHash)));

     // relying party
     CR( fido_assert_set_rp( fAssert, PAnsiChar( Utf8String( fRelyingParty ) ) ) );

     // user presence
     CR( fido_assert_set_up( fAssert, fUserPresence ) );
     CR( fido_assert_set_uv( fAssert, fUserVerification) );
end;

destructor TBaseFidoAssert.Destroy;
begin
     FreeAssert;

     inherited;
end;

procedure TBaseFidoAssert.PrepareAssert;
begin
     InitAssert;
     UpdateAssert;
end;

constructor TBaseFidoAssert.Create;
begin
     RandomInit(fClientHash, sizeof(fClientHash), False);

     fRelyingParty := 'localhost';
     fEnableHMACSecret := False;
     //fHMACSecret := '';
     fAssertType := ctCOSEES256;
     fUserPresence := FIDO_OPT_OMIT;
     fUserVerification := FIDO_OPT_OMIT;

     inherited Create;
end;

procedure TBaseFidoAssert.SetAssertType(const Value: TFidoCredentialType);
begin
     fAssertType := Value;
     UpdateAssert;
end;

procedure TBaseFidoAssert.SetClientData(const Value: string);
begin
     fClientData := Value;
     UpdateAssert;
end;

procedure TBaseFidoAssert.SetFmt(const Value: TFidoCredentialFmt);
begin
     fFmt := Value;
     UpdateAssert;
end;

procedure TBaseFidoAssert.SetHMACSecret(const Value: boolean);
begin
     fEnableHMACSecret := Value;
     UpdateAssert;
end;

procedure TBaseFidoAssert.SetHMACSecretValue(const Value: UTF8String);
begin
     fHMACSecret := Value;
     UpdateAssert;
end;

procedure TBaseFidoAssert.SetRelParty(const Value: string);
begin
     fRelyingParty := Value;
     UpdateAssert;
end;

procedure TBaseFidoAssert.SetUserIdent(const Value: fido_opt_t);
begin
     fUserVerification := Value;
     UpdateAssert;
end;

procedure TBaseFidoAssert.SetUserPresence(const Value: fido_opt_t);
begin
     fUserPresence := Value;
     UpdateAssert;
end;

procedure TBaseFidoAssert.CreateRandomCID;
begin
     RandomInit(fClientHash, sizeof(fClientHash), False);
     UpdateAssert;
end;

procedure TFidoAssert.AddAllowedCredential(cred: TBaseFido2Credentials);
var idLen : integer;
begin
     PrepareAssert;

     idLen := fido_cred_id_len(cred.fCred);
     if idLen > 0 then
        CR( fido_assert_allow_cred( fAssert, fido_cred_id_ptr(cred.fCred ) , idLen ) );
end;

// #########################################################
// #### Assertion - device
// #########################################################

{ TFidoAssert }

function TFidoAssert.Perform(dev: TFidoDevice; sPin : string; var cnt: integer): boolean;
var r : integer;
    pPin : PAnsiChar;
begin
     Result := False;

     fErr := '';
     PrepareAssert;

     if Length(fHMacSalt) > 0 then
        CR( fido_assert_set_hmac_salt( fAssert, @fHMacSalt[0], Length(fHMacSalt) ) );

     fExtensions := 0;
     if fEnableHMACSecret then
        fExtensions := fExtensions or FIDO_EXT_HMAC_SECRET;

     // hmac secret for testing...
     if fHMACSecret <> '' then
        CR( fido_assert_set_hmac_secret( fAssert, 0, PByte(@fHMACSecret[1]), Length(fHMACSecret) ) );

     // blob support
     if dev.HasBlobSupport then
        fExtensions := FIDO_EXT_LARGEBLOB_KEY or FIDO_EXT_CRED_BLOB;

     CR( fido_assert_set_extensions( fAssert, fExtensions ) );

     pPin := nil;
     if Length(sPin) > 0 then
        pPin := PAnsiChar( UTF8String( sPin ) );
     r := fido_dev_get_assert( dev.fDev, fAssert, pPin );

     if r = FIDO_OK then
     begin
          cnt := fido_assert_count(fAssert);
          Result := cnt > 0;
          if not Result then
             fErr := 'Count is zero';
     end
     else
         fErr := String( UTF8String( fido_strerr(r) ) );
end;

function TFidoAssert.GetAuthData( idx : integer ): TBytes;
begin
     assert( Assigned( fAssert ), 'No Assert handle aquired -> call perform first');
     Result := ptrToByteArr( fido_assert_authdata_ptr( fAssert, idx ), fido_assert_authdata_len( fAssert, idx) );
end;

function TFidoAssert.GetSig( idx : integer ): TBytes;
begin
     assert( Assigned( fAssert ), 'No Assert handle aquired -> call perform first');
     Result := ptrToByteArr( fido_assert_sig_ptr( fAssert, idx ), fido_assert_sig_len( fAssert, idx) );
end;

function TFidoAssert.GetSmallBlob(idx : integer): TBytes;
begin
     assert( Assigned( fAssert ), 'No Assert handle aquired -> call perform first');
     Result := ptrToByteArr( fido_assert_blob_ptr(fAssert, idx), fido_assert_blob_len(fAssert, idx));
end;

function TFidoAssert.GetHMAC(idx: integer): TBytes;
begin
     assert( Assigned( fAssert ), 'No Assert handle aquired -> call perform first');
     Result := ptrToByteArr( fido_assert_hmac_secret_ptr( fAssert, idx ), fido_assert_hmac_secret_len( fAssert, idx ) );
end;

function TFidoAssert.GetLargeBlob( idx : integer ): TBytes;
begin
     assert( Assigned( fAssert ), 'No Assert handle aquired -> call perform first');
     Result := ptrToByteArr( fido_assert_largeblob_key_ptr(fAssert, idx), fido_assert_largeblob_key_len(fAssert, idx));
end;

procedure TFidoAssert.SetHMACSecretSalt(salt: TBytes);
begin
     fHMacSalt := Copy( salt, 0, Length(salt) );
end;

// #########################################################
// #####
// #########################################################

{ TFidoAssertVerify }

// #########################################################
// #### Assertion verification
// #########################################################

constructor TFidoAssertVerify.Create;
begin
     inherited Create;

     fPK := nil;
     fErr := '';
end;

procedure TFidoAssertVerify.LoadPKFromStream(stream: TStream);
var len : integer;
begin
     stream.ReadBuffer(len, sizeof(len));
     SetLength(fPK, len);
     if (len > 0) then
        stream.ReadBuffer(fPK[0], len);
end;

function TFidoAssertVerify.Verify(authData, sig: TBytes; ext : integer = 0): boolean;
var r : integer;
begin
     if Length(authData) = 0 then
        raise EFidoPropertyException.Create('Error authdata block is nil');
     if Length(sig) = 0 then
        raise EFidoPropertyException.Create('Error sig block is nil');

     if GetKeyPtr = nil then
        InitPublikKey;

     if GetKeyPtr = nil then
        raise EFidoPropertyException.Create('No public key set!');

     if Length(fClientHash) = 0 then
        raise EFidoPropertyException.Create('Error no client hash set');

     InitAssert;
     try
        UpdateAssert;

        // hmac secret for testing...
        if fHMACSecret <> '' then
           CR( fido_assert_set_hmac_secret( fAssert, 0, PByte(@fHMACSecret[1]), Length(fHMACSecret) ) );

        CR( fido_assert_set_extensions( fAssert, ext ) );

        // authdata
        CR( fido_assert_set_count(fAssert, 1) );   // todo
        CR( fido_assert_set_authdata(fAssert, 0, @authdata[0], Length(authData)));

        CR( fido_assert_set_sig(fAssert, 0, @sig[0], Length(sig) ) );

        // verification!
        r := fido_assert_verify(fAssert, 0, Integer(fAssertType), GetKeyPtr);
        Result := r = FIDO_OK;

        if not Result then
           fErr := String( fido_strerr(r) );
     finally
            FreeAssert;
     end;
end;

procedure TFidoAssertVerify.InitPublikKey;
begin
     assert(Length(fPK) > 0, 'error no public key read - initialize with LoadPKfromStream');

     ClearPK;

     case fAssertType of
       ctCOSEES256: begin
                         fpk1 := es256_pk_new;
                         assert(Assigned(fpk1), 'Memory allocation form es256 failed');
                         CR( es256_pk_from_ptr( fpk1, @fPK[0], Length(fPK) ) );
                    end;
       ctCoseES384: begin
                         fpk4 := es384_pk_new;
                         assert(Assigned(fpk4), 'Memory allocation form es384 failed');
                         CR( es384_pk_from_ptr( fpk4, @fPK[0], Length(fPK) ) );
                    end;
       ctCoseEDDSA: begin
                         fpk2 := eddsa_pk_new;
                         assert(Assigned(fpk2), 'Memory allocation for EDDSA failed');
                         CR( eddsa_pk_from_ptr(fpk2, @fPK[0], Length(fPK) ) );
                    end;
       ctCoseRS256: begin
                         fpk3 := rs256_pk_new;
                         assert(Assigned(fpk3), 'Memory allocation for RS256 failed');
                         CR( rs256_pk_from_ptr( fpk3, @fPK[0], Length(fPK)) );
                    end;
     end;
end;

procedure TFidoAssertVerify.SetAssertType(const Value: TFidoCredentialType);
begin
     ClearPK;

     inherited;
end;


procedure TFidoAssertVerify.ClearPK;
begin
     if Assigned(fpk1) then
        es256_pk_free(fPk1);
     if Assigned(fpk2) then
        eddsa_pk_free(fpk2);
     if Assigned(fpk3) then
        rs256_pk_free(fpk3);
     if Assigned(fpk4) then
        es384_pk_free(fPK4);

     fPk1 := nil;
     fPK2 := nil;
     fPK3 := nil;
end;

function TFidoAssertVerify.GetKeyPtr: Pointer;
begin
     Result := fpk1;
     if not Assigned(Result) then
        Result := fpk2;
     if not Assigned(Result) then
        Result := fpk3;
end;

procedure TFidoAssertVerify.SetPK(const Value: TBytes);
begin
     fPK := Copy(Value, 0, Length(Value));
end;

destructor TFidoAssertVerify.Destroy;
begin
     ClearPK;

     inherited;
end;

procedure TFidoAssertVerify.LoadPKFromFile(fn: string);
var fs : TFileStream;
begin
     fs := TFileStream.Create(fn, fmOpenRead);
     try
        LoadPKFromStream(fs);
     finally
            fs.Free;
     end;
end;

// #########################################################
// ####
// #########################################################

{ TFido2CredentialManager }

// #########################################################
// #### Credential Management
// #########################################################

constructor TFido2CredentialManager.Create;
begin
     fRelayPartyList := TFido2RelayPartyList.Create(True);
     fResidentKeyList := TFido2ResidentKeyList.Create(True);

     inherited Create;
end;

destructor TFido2CredentialManager.Destroy;
begin
     Clear;
     fRelayPartyList.Free;
     fResidentKeyList.Free;

     inherited;
end;

procedure TFido2CredentialManager.ReadDev;
begin
     fNumResidentKeys := fido_credman_rk_existing( fMetaCredMan );
     fNumResidentKeysRemain := fido_credman_rk_remaining( fMetaCredMan );
end;

procedure TFido2CredentialManager.Clear;
begin
     if Assigned(fMetaCredMan) then
        fido_credman_metadata_free(fMetaCredMan);
     if Assigned(fCredManRP) then
        fido_credman_rp_free(fCredManRP);

     fMetaCredMan := nil;
     fCredManRP := nil;
     fRelayPartyList.Clear;
     fResidentKeyList.Clear;
end;

function TFido2CredentialManager.Open(dev: TFidoDevice; pin: string; var ErrMsg : string) : boolean;
var sPin : UTF8String;
    pPin : PAnsiChar;
    cnt : integer;
    obj : TFido2ResidentKey;
    rk : Pfido_credman_rk_t;
    r : integer;
begin
     Result := False;
     ErrMsg := '';

     // ###########################################
     // #### First check if the device actually supports credential management
     if not dev.SupportCredManager then
     begin
          ErrMsg := 'Device does not support the credential manager API';
          exit;
     end;

     Clear;

     pPin := nil;
     sPin := UTF8String(pin);
     if sPin <> '' then
        pPin := PAnsiChar( sPin );

     fMetaCredMan := fido_credman_metadata_new;
     assert( Assigned(fMetaCredMan), 'Error memory allocation for credential manager failed');
     CR( fido_credman_get_dev_metadata( dev.fDev, fMetaCredMan, pPin) );

     fCredManRP := fido_credman_rp_new;
     assert( Assigned(fCredManRP), 'Error memory allocation for RP credential manager failed');

     r := fido_credman_get_dev_rp( dev.fDev, fCredManRP, pPin );
     // returns FIDO_ERR_INVALID_COMMAND - on Firmware 5.1.2
     if r <> FIDO_OK then
     begin
          ErrMsg := String( fido_strerr(r) );
          Clear;
          exit;
     end;

     ReadDev;
     ReadRelayingParties;

     for cnt := 0 to fRelayPartyList.Count - 1 do
     begin
          rk := fido_credman_rk_new;
          try
             assert( Assigned( rk ), 'Failed to allocate memory for Resident Key');
             r := fido_credman_get_dev_rk( dev.fDev, PAnsiChar( UTF8String( fRelayPartyList[cnt].ID ) ), rk, pPin );

             // returns FIDO_ERR_INVALID_COMMAND - on Firmware 5.1.2
             if r <> FIDO_OK then
             begin
                  ErrMsg := String( fido_strerr(r) );
                  Clear;
                  exit;
             end;

             obj := TFido2ResidentKey.Create( rk );
             fResidentKeyList.Add( obj );
          finally
                 fido_credman_rk_free(rk);
          end;
     end;

     Result := True;
end;

procedure TFido2CredentialManager.ReadRelayingParties;
var cnt : integer;
    count : integer;
    obj : TFido2RelayParty;
begin
     count := fido_credman_rp_count( fCredManRP );

     for cnt := 0 to count - 1 do
     begin
          obj := TFido2RelayParty.Create( fCredManRP, cnt );
          fRelayPartyList.Add( obj );
     end;
end;

procedure TFido2CredentialManager.DelResidentKey(dev : TFidoDevice; credId: TBytes; pin : string);
var sPin : UTF8String;
    pPin : PAnsiChar;
begin
     assert(Length(credId) > 0, 'No credential ID');

     pPin := nil;
     sPin := UTF8String(pin);
     if sPin <> '' then
        pPin := PAnsiChar( sPin );

     CR( fido_credman_del_dev_rk(dev.fDev, @credId[0], Length(credId), pPin) );
end;

{ TFido2RelayParty }

constructor TFido2RelayParty.Create( rp : Pfido_credman_rp_t; idx : size_t );
var pS : PAnsiChar;
    len : integer;
begin
     inherited Create;

     fIdx := idx;

     pS := fido_credman_rp_id( rp, idx );
     if Assigned(pS) then
        fID := String( pS );
     pS := fido_credman_rp_name( rp, idx );
     if Assigned(pS) then
        fName := String( pS );
     len := fido_credman_rp_id_hash_len( rp, idx );
     SetLength(fHash, len);
     if len > 0 then
        Move( fido_credman_rp_id_hash_ptr( rp, idx )^, fHash[0], len );
end;

destructor TFido2RelayParty.Destroy;
begin
     inherited;
end;

{ TFido2ResidentKey }

constructor TFido2ResidentKey.Create(rk: Pfido_credman_rk_t);
var cnt : integer;
    count : integer;
    cred : Pfido_cred_t;
begin
     inherited Create;

     count := fido_credman_rk_count( rk );
     SetLength(fCredList, count);
     for cnt := 0 to count - 1 do
     begin
          cred := fido_credman_rk( rk, cnt );
          if cred <> nil then
             fCredList[cnt] := TFido2Credential.Create( cred );
     end;
end;

destructor TFido2ResidentKey.Destroy;
var cnt : integer;
begin
     for cnt := 0 to Length(fCredList) - 1 do
         fCredList[cnt].Free;
     fCredList := nil;

     inherited;
end;

function TFido2ResidentKey.GetCred(idx: integer): TFido2Credential;
begin
     if idx >= Length(fCredList) then
        raise EFidoPropertyException.Create('Index out of bounds');
     Result := fCredList[idx];
end;

{ TFido2Credential }

constructor TFido2Credential.Create(cred: Pfido_cred_t);
begin
     inherited Create;

     fDisplaNamy := ptrToStr( fido_cred_display_name(cred) );
     fFmt := TFidoCredentialFmt( fido_cred_fmt( cred ) );
     fRelyingParty := ptrToStr( fido_cred_rp_id( cred ) );
     fRelyingPartyName := ptrToStr( fido_cred_rp_name( cred ) );
     fUserId := ptrToByteArr( fido_cred_user_id_ptr( cred ), fido_cred_user_id_len( cred ) );
     fUserName := ptrToStr( fido_cred_user_name( cred ) );
     fDisplaNamy := ptrToStr( fido_cred_display_name( cred ) );

     fAuthData := ptrToByteArr( fido_cred_authdata_ptr( cred ), fido_cred_authdata_len( cred ) );
     fCredType := TFidoCredentialType( fido_cred_type( cred ) );
     fCredId := ptrToByteArr( fido_cred_id_ptr( cred ), fido_cred_id_len( cred ) );
     fSig := ptrToByteArr( fido_cred_sig_ptr( cred ), fido_cred_sig_len( cred ) );
     fx509 := ptrToByteArr( fido_cred_x5c_ptr( cred ), fido_cred_x5c_len( cred ) );
     // fCredGuid := ptrToByteArr( fido_cred_aaguid_ptr( cred ), fido_cred_aaguid_len( cred ) );
end;

function TFidoDevice.GetFirmware: string;
begin
     Result := Format('%d.%d.%d', [fDevMajor, fDevMinor, fDevBuild] ) ;
end;

function TFidoDevice.GetHasPin: boolean;
begin
     Assert( Assigned(fDev), 'error no device assigned');

     Result := fido_dev_has_pin( fDev );
end;

function TFidoDevice.GetLargeBlob: TCborItem;
var cborPtr : PByte;
    cborLen : size_t;
begin
     Assert( Assigned(fDev), 'error no device assigned');
     Result := nil;

     if not fHasBlobSupport then
        raise EFidoPropertyException.Create('Error: blobs not supported by this device');

     CR( fido_dev_largeblob_get_array( fDev, cborPtr, cborLen ) );
     if cborLen > 0 then
        Result := TCborDecoding.DecodeData(cborPtr, cborLen);
end;

function TFidoDevice.GetLargeBlobKey(key: TBytes): TBytes;
var blobPtr : PByte;
    blobLen : size_t;
begin
     Assert( Assigned(fDev), 'error no device assigned');
     Assert( Length(key) > 0, 'Error no key defined');
     Result := nil;

     if not fHasBlobSupport then
        raise EFidoPropertyException.Create('Error: blobs not supported by this device');

     CR( fido_dev_largeblob_get( fDev, @key[0], Length(key), blobPtr, blobLen) );

     Result := ptrToByteArr(blobPtr, blobLen);
end;

function TFidoDevice.GetLargeBlobRaw: TBytes;
var cborPtr : PByte;
    cborLen : size_t;
begin
     Assert( Assigned(fDev), 'error no device assigned');

     if not fHasBlobSupport then
        raise EFidoPropertyException.Create('Error: blobs not supported by this device');

     CR( fido_dev_largeblob_get_array( fDev, cborPtr, cborLen ) );
     Result := ptrToByteArr(cborPtr, cborLen);
end;

function TFidoDevice.GetTouchStatus(waitMs: integer): integer;
begin
     Assert( Assigned(fDev), 'error no device assigned');

     CR( fido_dev_get_touch_status( fDev, Result, waitMs) );
end;

procedure TFidoDevice.ForceFido2;
begin
     Assert( Assigned(fDev), 'error no device assigned');

     fido_dev_force_fido2( fDev );
end;

procedure TFidoDevice.ForceU2F;
begin
     Assert( Assigned(fDev), 'error no device assigned');

     fido_dev_force_u2f( fDev );
end;

procedure TBaseFido2Credentials.SavePKToFile(fn: String);
var fs : TFileStream;
begin
     fs := TFileStream.Create( fn, fmCreate );
     try
        SavePKToStream(fs);
     finally
            fs.Free;
     end;
end;

procedure TBaseFido2Credentials.SaveUIDToFile(fn: string);
var fs : TFileStream;
begin
     fs := TFileStream.Create( fn, fmCreate );
     try
        SaveUIDToStream(fs);
     finally
            fs.Free;
     end;
end;

procedure TBaseFido2Credentials.SaveCredIDToFile(fn: string);
var fs : TFileStream;
begin
     fs := TFileStream.Create( fn, fmCreate );
     try
        SaveCredIDToStream(fs);
     finally
            fs.Free;
     end;
end;

// ########################################################
// ####
// ########################################################

{ TFidoBiometricTemplate }

// ########################################################
// #### Biometric template
// ########################################################

function TFidoBiometricTemplate.GetID: TBytes;
begin
     Result := ptrToByteArr( fido_bio_template_id_ptr( fTemplate ), fido_bio_template_id_len( fTemplate ) );
end;

function TFidoBiometricTemplate.GetString: string;
begin
     Result := String( fido_bio_template_name( fTemplate ) );
end;

procedure TFidoBiometricTemplate.SetId(const Value: TBytes);
var pB : PByte;
begin
     pB := nil;
     if Length(Value) > 0 then
        pb := @Value[0];

     CR( fido_bio_template_set_id( fTemplate, pb, Length(Value) ) );
end;

procedure TFidoBiometricTemplate.SetString(const Value: string);
begin
     CR( fido_bio_template_set_name( fTemplate, PAnsiChar( UTF8String( Value ) ) ) );
end;

constructor TFidoBiometricTemplate.Create;
begin
     fTemplate := fido_bio_template_new;
     fOwnsTemplate := True;

     if not Assigned(fTemplate) then
        raise EFidoAllocException.Create('Error allocating template');

     inherited;
end;

constructor TFidoBiometricTemplate.CreateByRef(tpl: Pfido_bio_template_t);
begin
     fTemplate := tpl;
     fOwnsTemplate := False;

     if not Assigned(fTemplate) then
        raise EFidoAllocException.Create('No Template Assigned');

     inherited Create;
end;

destructor TFidoBiometricTemplate.Destroy;
begin
     if fOwnsTemplate then
        fido_bio_template_free(fTemplate);

     inherited;
end;

{ TFidoBiometricTplArray }

function TFidoBiometricTplArray.GetCount: integer;
begin
     Result := fArrObj.Count;
end;

function TFidoBiometricTplArray.GetItem(index: integer): TFidoBiometricTemplate;
begin
     assert( index < fArrObj.Count, 'Index out of bounds');
     Result := fArrObj[index];
end;

constructor TFidoBiometricTplArray.Create;
begin
     inherited Create;

     Init;
end;

procedure TFidoBiometricTplArray.Clear;
begin
     if Assigned(fArrObj) then
     begin
          FreeAndNil(fArrObj);
          fido_bio_template_array_free(fTplArr);
          fTplArr := nil;
     end;
end;

procedure TFidoBiometricTplArray.Init;
begin
     if not Assigned(fArrObj) then
     begin
          fArrObj := TFidoBiometricTemplateArr.Create;

          fTplArr := fido_bio_template_array_new;
          if not Assigned(fTplArr) then
             raise EFidoAllocException.Create('Error could not allocate template array');
     end;
end;

procedure TFidoBiometricTplArray.InitFromDev(dev: TFidoBiometricDevice;
  pin: string);
var pPin : PAnsiChar;
    cnt : integer;
begin
     Clear;
     Init;

     pPin := nil;
     if pin <> '' then
        pPin := PAnsiChar( UTF8String( pin ) );
     CR( fido_bio_dev_get_template_array(dev.fDev, fTplArr, pPin) );

     for cnt := 0 to fido_bio_template_array_count( fTplArr ) - 1 do
         fArrObj.Add( TFidoBiometricTemplate.CreateByRef( fido_bio_template( fTplArr, cnt ) ) );
end;

destructor TFidoBiometricTplArray.Destroy;
begin
     Clear;

     inherited;
end;

{ TFidoBiometricEnroll }

constructor TFidoBiometricEnroll.Create;
begin
     inherited Create;

     fEnroll := fido_bio_enroll_new;
     if not Assigned(fEnroll) then
        raise EFidoAllocException.Create('Error could not allocate enroll');
end;

destructor TFidoBiometricEnroll.Destroy;
begin
     if Assigned(fEnroll) then
        fido_bio_enroll_free(fEnroll);

     inherited;
end;

function TFidoBiometricEnroll.LastStatus: byte;
begin
     Result := fido_bio_enroll_last_status( fEnroll );
end;

function TFidoBiometricEnroll.RemainingSamples: byte;
begin
     Result := fido_bio_enroll_remaining_samples( fEnroll );
end;

{ TFidoBiometricDevice }

function TFidoBiometricDevice.TemplateArr( pin : string ): TFidoBiometricTplArray;
begin
     Result := TFidoBiometricTplArray.Create;
     Result.InitFromDev( self, pin );
end;

function TFidoBiometricDevice.EnrollBegin(pin: string;
  template: TFidoBiometricTemplate; timeout : UInt32): TFidoBiometricEnroll;
var pPin : PAnsiChar;
begin
     pPin := nil;
     if Length(pin) > 0 then
        pPin := PAnsiChar(UTF8String( pin ));
     fEnroll := TFidoBiometricEnroll.Create;

     CR( fido_bio_dev_enroll_begin( fDev, template.fTemplate, fEnroll.fEnroll, timeout, pPin) );

     Result := fEnroll;
end;

procedure TFidoBiometricDevice.EnrollContinue(template: TFidoBiometricTemplate;
  timeout: UInt32);
begin
     if not Assigned(fEnroll) then
        raise EFidoBaseException.Create('Error - call EnrollBegin first');

     CR( fido_bio_dev_enroll_continue(fDev, template.fTemplate, fEnroll, timeout) );
end;

procedure TFidoBiometricDevice.EnrollCancel;
begin
     if not Assigned(fEnroll) then
        raise EFidoBaseException.Create('Error - call EnrollBegin first');

     CR( fido_bio_dev_enroll_cancel( fDev ) );

     FreeAndNil(fEnroll);
end;

procedure TFidoBiometricDevice.EnrollRemove(template: TFidoBiometricTemplate;
  pin: string);
var pPin : PAnsiChar;
begin
     if not Assigned(fEnroll) then
        raise EFidoBaseException.Create('Error - call EnrollBegin first');

     pPin := nil;
     if Length(pin) > 0 then
        pPin := PAnsiChar(UTF8String( pin ));

     Cr( fido_bio_dev_enroll_remove( fDev, template.fTemplate, pPin) );
end;

destructor TFidoBiometricDevice.Destroy;
begin
     fEnroll.Free;
     fInfo.Free;

     inherited;
end;

function TFidoBiometricDevice.GetInfo: TFidoBiometricInfo;
begin
     if not Assigned(fInfo) then
     begin
          fInfo := TFidoBiometricInfo.Create;
          CR( fido_bio_dev_get_info( fDev, fInfo.fInfo ) );
     end;

     Result := fInfo;
end;

{ TFidoBiometricInfo }

constructor TFidoBiometricInfo.Create;
begin
     inherited Create;

     fInfo := fido_bio_info_new;
     if not Assigned(fInfo) then
        EFidoAllocException.Create('Error could not allocate bio info object');
end;

destructor TFidoBiometricInfo.Destroy;
begin
     if Assigned( fInfo ) then
        fido_bio_info_free(fInfo);

     inherited;
end;

function TFidoBiometricInfo.MaxSamples: byte;
begin
     Result := fido_bio_info_max_samples( fInfo );
end;

function TFidoBiometricInfo.DevType: byte;
begin
     Result := fido_bio_info_type( fInfo );
end;

end.
