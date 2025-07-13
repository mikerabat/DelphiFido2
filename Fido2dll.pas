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


// fido2 dll import file for fido2.dll V 1.16.0 and higher
// the file is basically a conversion of the imported header files of the fido2.dll
// based on the sources in: https://github.com/Yubico/libfido2

// check out: https://developers.yubico.com/libfido2/
// for more information

unit Fido2dll;

interface

const libFido = 'fido2.dll';

{$DEFINE FIDODLL_V1_15}
{$DEFINE FIDODLL_V1_16}

{$MinEnumSize 4}  // C headers seem to have 4 bytes minimum enum size

type
  size_t = NativeUInt;
  fido_sigset_t = Integer;
  Pfido_sigset_t = ^fido_sigset_t;
  PPAnsiChar = ^PAnsiChar;

// ###########################################
// #### from types.h
// ###########################################
type
  fido_log_handler_t = procedure(msg : PAnsiChar); cdecl;

type
  fido_opt_t = ( FIDO_OPT_OMIT,    // use authenticator's default
                 FIDO_OPT_FALSE,   // explicitly set option to false
                 FIDO_OPT_TRUE );  // explicitly set option to true

  Pfido_dev = Pointer;
  fido_dev_rx_t = function( dev : Pfido_dev; flag : Byte; buf : PByte; n : size_t; count : integer) : integer; cdecl;
  fido_dev_transport_t = packed record
   rx : fido_dev_rx_t;
   tx : fido_dev_rx_t;
  end;
  Pfido_dev_transport_t = ^fido_dev_transport_t;

  TFidoHandle = Pointer;
  fido_dev_io_open_t = function ( inp : PAnsiChar ) : TFidoHandle; cdecl;
  fido_dev_io_close_t = procedure( fidoHdl : TFidoHandle); cdecl;
  fido_dev_io_read_t = function ( fidoHdl : TFidoHandle; buf : PByte; n : size_t; count : integer) : integer; cdecl;
  fido_dev_io_write_t = function( fidoHdl : TFidoHandle; buf : PByte; n : size_t) : integer; cdecl;


  fido_dev_io = packed record
    open : fido_dev_io_open_t;
	   close : fido_dev_io_close_t;
	   read : fido_dev_io_read_t ;
	   write : fido_dev_io_write_t;
  end;
  fido_dev_io_t = fido_dev_io;
  Pfido_dev_io_t = ^fido_dev_io_t;

  fido_dev_info = packed record
	   path : PAnsiChar;         // device path
	   vendor_id : Int16;        // 2-byte vendor id
	   product_id : Int16;       // 2-byte product id
	   manufacturer : PAnsiChar; // manufacturer string
	   product : PAnsiChar;      // product string
    io : fido_dev_io_t;       // io functions
    transport : fido_dev_transport_t; // transport functions
  end;
  fido_dev_info_t = fido_dev_info;

  fido_ctap_info = packed record
	   nonce : UInt64;    // echoed nonce
	   cid : UInt32;      // channel id
	   protocol : UInt8;  // ctaphid protocol id
	   major : UInt8;     // major version number
	   minor : UInt8;     // minor version number
	   build : UInt8;     // build version number
	   flags : Uint8;     // capabilities flags; see FIDO_CAP_*
  end;
  fido_ctap_info_t = fido_ctap_info;

  fido_dev = packed record
	   nonce : UInt64;            // issued nonce
	   attr : fido_ctap_info_t;   // device attributes
	   cid : UInt32;              // assigned channel id
    path : PAnsiChar;          // device Path
	   io_handle : Pointer;       // abstract i/o handle
	   io : fido_dev_io_t;        // i/o functions & data
    io_own : boolean;          // device has own io/transport
	   rx_len : size_t;           // length of HID input reports
	   tx_len : size_t;           // length of HID output reports
	   flags : integer;           // internal flags; see FIDO_DEV_*
    transport : fido_dev_transport_t; // transport functions
    maxmsgsize : UINT64;       // max message size
    timeout_ms : Integer;      // read timeout in ms
  end;
  fido_dev_t = fido_dev;


// ###########################################
// #### from param.h
// ###########################################


// Authentication data flags.
const CTAP_AUTHDATA_USER_PRESENT	= $01;
      CTAP_AUTHDATA_USER_VERIFIED	= $04;
      CTAP_AUTHDATA_ATT_CRED		= $40;
      CTAP_AUTHDATA_EXT_DATA		= $80;

// CTAPHID command opcodes.
      CTAP_CMD_PING	= $01;
      CTAP_CMD_MSG	= $03;
      CTAP_CMD_LOCK	= $04;
      CTAP_CMD_INIT	= $06;
      CTAP_CMD_WINK	= $08;
      CTAP_CMD_CBOR	= $10;
      CTAP_CMD_CANCEL	= $11;
      CTAP_KEEPALIVE	= $3b;
      CTAP_FRAME_INIT	= $80;

// CTAPHID CBOR command opcodes.
      CTAP_CBOR_MAKECRED		= $01;
      CTAP_CBOR_ASSERT		= $02;
      CTAP_CBOR_GETINFO		= $04;
      CTAP_CBOR_CLIENT_PIN		= $06;
      CTAP_CBOR_RESET			= $07;
      CTAP_CBOR_NEXT_ASSERT		= $08;
      CTAP_CBOR_BIO_ENROLL_PRE	= $40;
      CTAP_CBOR_CRED_MGMT_PRE		= $41;

// U2F command opcodes.
      U2F_CMD_REGISTER	= $01;
      U2F_CMD_AUTH	= $02;

// U2F command flags.
      U2F_AUTH_SIGN	= $03;
      U2F_AUTH_CHECK	= $07;

// ISO7816-4 status words.
      SW_CONDITIONS_NOT_SATISFIED	= $6985;
      SW_WRONG_DATA	= $6a80;
      SW_NO_ERROR	= $9000;

// HID Broadcast channel ID.
      CTAP_CID_BROADCAST	= $ffffffff;

      CTAP_INIT_HEADER_LEN	 =	7;
      CTAP_CONT_HEADER_LEN	=	5;

// Expected size of a HID report in bytes.
      CTAP_MAX_REPORT_LEN = 64;
      CTAP_MIN_REPORT_LEN = 8;

// CTAP capability bits.
      FIDO_CAP_WINK =	$01; // if set, device supports CTAP_CMD_WINK
      FIDO_CAP_CBOR	= $04; // if set, device supports CTAP_CMD_CBOR
      FIDO_CAP_NMSG	= $08; // if set, device doesn't support CTAP_CMD_MSG

// Supported COSE algorithms.
      COSE_UNSPEC	= 0;
      COSE_ES256	= -7;
      COSE_EDDSA	= -8;
      COSE_ES384	= -35;
      COSE_RS256	= -257;
      COSE_RS1	= -65535;

// Supported COSE types.
      COSE_KTY_OKP	= 1;
      COSE_KTY_EC2	= 2;
      COSE_KTY_RSA	= 3;

// Supported curves.
      COSE_P256	= 1;
      COSE_P384	= 2;
      COSE_ED25519	= 6;

// Supported extensions.
      FIDO_EXT_HMAC_SECRET =	$01;
      FIDO_EXT_CRED_PROTECT = $02;
      FIDO_EXT_LARGEBLOB_KEY = $04;
      FIDO_EXT_CRED_BLOB	= $08;
      FIDO_EXT_MINPINLEN	= $10;

// Supported enterprise attestation modes.
// to be used with fido_cred_set_entattest. Default is 0
      FIDO_ENTATTEST_NONE = 0;
      FIDO_ENTATTEST_VENDOR	= 1;
      FIDO_ENTATTEST_PLATFORM	= 2;


// supported credential protection policies
      FIDO_CRED_PROT_UV_OPTIONAL = $01;
      FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID = $02;
      FIDO_CRED_PROT_UV_REQUIRED = $03;

// maximum message size
      FIDO_MAXMSG = 2048;

// Recognised UV modes.
      FIDO_UV_MODE_TUP	= $0001; // internal test of user presence
      FIDO_UV_MODE_FP		= $0002; // internal fingerprint check
      FIDO_UV_MODE_PIN	= $0004; // internal pin check
      FIDO_UV_MODE_VOICE	= $0008; //internal voice recognition
      FIDO_UV_MODE_FACE	= $0010; //internal face recognition
      FIDO_UV_MODE_LOCATION	= $0020; //internal location check
      FIDO_UV_MODE_EYE	= $0040; //internal eyeprint check
      FIDO_UV_MODE_DRAWN	= $0080; //internal drawn pattern check
      FIDO_UV_MODE_HAND	= $0100; //internal handprint verification
      FIDO_UV_MODE_NONE	= $0200; //TUP/UV not required
      FIDO_UV_MODE_ALL	= $0400; //all supported UV modes required
      FIDO_UV_MODE_EXT_PIN	= $0800; // external pin verification
      FIDO_UV_MODE_EXT_DRAWN	= $1000; //external drawn pattern check


// ######################################################
// #### blob.h
// ######################################################

type
  fido_blob = packed record
    ptr : PByte;
    len : size_t;
  end;
  fido_blob_t = fido_blob;
  Pfido_blob_t = ^fido_blob_t;

  fido_blob_array = packed record
    ptr : Pfido_blob_t;
	   len : size_t;
  end;
  fido_blob_array_t = fido_blob_array;

// ######################################################
// #### type.h
// ######################################################

// COSE ES256 (ECDSA over P-256 with SHA-256) public key
type
  es256_pk = packed record
    x : Array[0..31] of byte;
    y : Array[0..31] of byte;
  end;
  es256_pk_t = es256_pk;

// COSE ES256 (ECDSA over P-256 with SHA-256) (secret) key
  es256_sk = packed record
	   d : Array[0..31] of byte;
  end;
  es256_sk_t = es256_sk;

// COSE ES384 (ECDSA over P-384 with SHA-384) public key */
  es384_pk = packed record
    x : Array[0..47] of byte;
    y : Array[0..47] of byte;
  end;
  es384_pk_t = es384_pk;
  Pes384_pk_t = ^es384_pk_t;

// COSE RS256 (2048-bit RSA with PKCS1 padding and SHA-256) public key
  rs256_pk = packed record
    n : Array[0..255] of Byte;
    e : Array[0..2] of Byte;
  end;
  rs256_pk_t = rs256_pk;

// COSE EDDSA (ED25519)
  eddsa_pk = packed record
    x : Array[0..31] of Byte;
  end;
  eddsa_pk_t = eddsa_pk;

// PACKED_TYPE(fido_authdata_t,
  fido_authdata = packed record
    rp_id_hash : Array[0..31] of Byte; // sha256 of fido_rp.id
    flags : Byte;                      // user present/verified
    sigcount : UInt32;	                // signature counter
	// actually longer ?? what does that mean?
   end;
   fido_authdata_t = fido_authdata;

//PACKED_TYPE(fido_attcred_raw_t,
  fido_attcred_raw = packed record
	   aaguid : Array[0..15] of Byte; // credential's aaguid
	   id_len : UInt16;               // credential id length
	   body : PByte; // uint8_t       body[];     // credential id + pubkey // todo: verify that this is translation is correct
  end;
  fido_attcred_raw_t = fido_attcred_raw;

  fido_attcred = packed record
    aaguid : Array[0..15] of Byte; // credential's aaguid
	   id : fido_blob_t;              // credential id
    case typ : integer of                // credential's cose algorithm
      COSE_ES256 : (es256 : es256_pk_t);
      COSE_ES384 : (es384 : es384_pk_t );
		    COSE_RS256 : (rs256 : rs256_pk_t);
		    COSE_EDDSA : (eddsa : eddsa_pk_t);
  end;
  fido_attcred_t = fido_attcred;

  fido_attstmt = packed record
    	certinfo : fido_blob_t; // tpm attestation TPMS_ATTEST structure
	    pubarea : fido_blob_t;  // tpm attestation TPMT_PUBLIC structure
	    cbor : fido_blob_t;     // cbor-encoded attestation statement
	    x5c : fido_blob_t;      // attestation certificate
	    sig : fido_blob_t ;     // attestation signature
	    alg : integer;          // attestation algorithm (cose)
  end;
  fido_attstmt_t = fido_attstmt;

  fido_rp = packed record
    id : PAnsiChar; //relying party id
    name : PAnsiChar; //relying party name
  end;
  fido_rp_t = fido_rp;

  fido_user = packed record
    id : fido_blob_t; // required
    icon : PAnsiChar; // optional
    name : PAnsiChar; // optional
    display_name : PAnsiChar; // required
  end;
  fido_user_t = fido_user;

  fido_cred_ext = packed record
	   mask : integer;      // enabled extensions
	   prot : integer;      // protection policy
	   minpinlen : size_t;  // minimum pin length #
  end;
  fido_cred_ext_t = fido_cred_ext;


  fido_cred = packed record
    cd : fido_blob_t;            // client data
	   cdh : fido_blob_t;           // client data hash
	   rp : fido_rp_t;              // relying party
	   user : fido_user_t;          // user entity
	   excl : fido_blob_array_t;    // list of credential ids to exclude
	   rk : fido_opt_t;             // resident key
	   uv : fido_opt_t;             // user verification
	   ext : integer;               // enabled extensions
	   typ : integer;               // cose algorithm
    fmt : PAnsiChar;             // credential format
	   authdata_ext : integer;      // decoded extensions
	   authdata_cbor : fido_blob_t; // raw cbor payload
	   authdata : fido_authdata_t;  // decoded authdata payload
	   attcred : fido_attcred_t;    // returned credential (key + id)
	   attstmt : fido_attstmt_t;    // attestation statement (x509 + sig)
    largeblob_key : fido_blob_t; // decoded large blob key
	   blob : fido_blob_t;          // CTAP 2.1 credBlob
  end;
  fido_cred_t = fido_cred;

  fido_assert_extattr = packed record
    mask : integer;                 // decoded extensions
    hmac_secret_enc : fido_blob_t;  // hmac secret, encrypted
    blob : fido_blob_t;             // decoded CTAP 2.1 credBlob
  end;
  fido_assert_extattr_t = fido_assert_extattr;

  _fido_assert_stmt = packed record
	   id : fido_blob_t;                      // credential id
	   user : fido_user_t;                    // user attributes
	   hmac_secret : fido_blob_t;             // hmac secret
	   authdata_ext : fido_assert_extattr_t;  // decoded extensions
	   authdata_cbor : fido_blob_t;           // raw cbor payload
	   authdata : fido_authdata_t;            // decoded authdata payload
	   sig : fido_blob_t;                     // signature of cdh + authdata
    largeblob_key : fido_blob_t;           // decoded large blob key
  end;
  fido_assert_stmt = _fido_assert_stmt;
  Pfido_assert_stmt = ^fido_assert_stmt;

  fido_assert_ext = packed record
    mask : integer;          // enabled extensions
	   hmac_salt : fido_blob_t; // optional hmac-secret salt
  end;
  fido_assert_ext_t = fido_assert_ext;

  fido_assert = packed record
   rp_id : PAnsiChar;          // relying party id
   cd : fido_blob_t;           // client data
	  cdh : fido_blob_t;          // client data hash
	  allow_list : fido_blob_array_t;   // list of allowed credentials
	  up : fido_opt_t;            // user presence
	  uv : fido_opt_t;            // user verification
	  ext : fido_assert_ext_t;    // enabled extensions
	  stmp : Pfido_assert_stmt;   // array of expected assertions
	  stmt_cnt : size_t;          // number of allocated assertions
	  stmt_len : size_t;          // number of received assertions
  end;
  fido_assert_t = fido_assert;

  fido_opt_array = packed record
	   name : PPAnsiChar;
	   value : PBoolean;
	   len : size_t;
  end;
  fido_opt_array_t = fido_opt_array;

  fido_str_array = packed record
	   ptr : PPAnsichar;
	   len : size_t;
  end;
  fido_str_array_t = fido_str_array;

  fido_byte_array = packed record
    ptr : PByte;
	   len : size_t;
  end;
  fido_byte_array_t = fido_byte_array;

  fido_algo = packed record
    typ : PAnsiChar;
    cose : integer;
  end;
  fido_algo_t = fido_algo;
  Pfido_algo_t = ^fido_algo_t;

  fido_algo_array = packed record
    ptr : Pfido_algo_t;
    len : size_t;
  end;
  fido_algo_array_t = fido_algo_array;

  fido_cert_array = packed record
	   name : PPAnsichar;
	   value : PUInt64;
	   len : size_t;
  end;
  fido_cert_array_t = fido_cert_array;

  fido_cbor_info = packed record
	   versions : fido_str_array_t;   // supported versions: fido2|u2f
	   extensions : fido_str_array_t; // list of supported extensions
    transports : fido_str_array_t; // list of supported transports
    aaguid : Array[0..15] of Byte; // aaguid
	   options : fido_opt_array_t;    // list of supported options
	   maxmsgsiz : UInt64;            // maximum message size
	   protocols : fido_byte_array_t; // supported pin protocols
    algorithms : fido_algo_array_t;// list of supported algorithms
    maxcredcntlst : Uint64;        // max of credentials in list
	   maxcredidlen : Uint64;         // max credential ID length
    fwversion : UINT64;            // firmware version
    maxcredbloblen : UINT64;       // max credBlob length
    maxlargeblob : UINT64;         // max largeBlob array length
    maxrpid_minlen : UINT64;       // max rpid in set_pin_minlen_rpid
	   minpinlen : UINT64;            // min pin len enforced
	   uv_attempts : UINT64;          // platform uv attempts
	   uv_modality : UINT64;          // bitmask of supported uv types
	   rk_remaining : Int64;          // remaining resident credentials
	   new_pin_reqd : Boolean;        // new pin required
	   certs : fido_cert_array_t;     // associated certifications
  end;
  fido_cbor_info_t = fido_cbor_info;


//PACKED_TYPE(fido_ctap_info_t,
// defined in section 8.1.9.1.3 (CTAPHID_INIT) of the fido2 ctap spec


// ###########################################
// #### fido.h
// ###########################################

// fido internal:
type
  Pfido_assert_t = ^fido_assert_t;
  PPfido_assert_t = ^Pfido_assert_t;

  Pfido_cbor_info_t = ^fido_cbor_info_t;
  PPfido_cbor_info_t = ^Pfido_cbor_info_t;

  Pfido_cred_t = ^fido_cred_t;
  PPfido_cred_t = ^Pfido_cred_t;

  Pfido_dev_t = ^fido_dev_t;
  PPfido_dev_t = ^Pfido_dev_t;

  Pfido_dev_info_t = ^fido_dev_info_t;
  PPfido_dev_info_t = ^Pfido_dev_info_t;

  Pes256_pk_t = ^es256_pk_t;
  PPes256_pk_t = ^Pes256_pk_t;

  Pes256_sk_t = ^es256_sk_t;
  PPes256_sk_t = ^Pes256_sk_t;

  Prs256_pk_t = ^rs256_pk_t;
  PPrs256_pk_t = ^Prs256_pk_t;

  Peddsa_pk_t = ^eddsa_pk_t;
  PPeddsa_pk_t = ^Peddsa_pk_t;

// opensl
  EVP_PKEY = packed record end;
  PEVP_PKEY = ^EVP_PKEY;
  PPEVP_PKEY = ^PEVP_PKEY;
  EC_KEY = packed record end;
  PEC_KEY = ^EC_KEY;
  RSA = packed record end;
  PRSA = ^RSA;


// credman.h
  fido_credman_metadata = packed record
    rk_existing : UInt64;
    rk_remaining : UInt64;
  end;
  fido_credman_metadata_t = fido_credman_metadata;
  Pfido_credman_metadata_t = ^fido_credman_metadata_t;

  fido_credman_single_rp = packed record
    rp_entity : fido_rp_t;
    rp_id_hash : fido_blob_t;
  end;
  Pfido_credman_single_rp = ^fido_credman_single_rp;

  fido_credman_rp = packed record
	   ptr : Pfido_credman_single_rp;
	   n_alloc : size_t; // number of allocated entries
	   n_rx : size_t;    // number of populated entries
  end;
  fido_credman_rp_t = fido_credman_rp;
  Pfido_credman_rp_t = ^fido_credman_rp_t;

  _fido_credman_rk = packed record
    ptr : Pfido_cred_t;
	   n_alloc : size_t; // number of allocated entries
	   n_rx : size_t;    // number of populated entries
  end;
  fido_credman_rk_t = _fido_credman_rk;
  Pfido_credman_rk_t = ^fido_credman_rk_t;

// ###########################################
// #### fido\err.h
// ###########################################

const  FIDO_ERR_SUCCESS		= $00;
       FIDO_ERR_INVALID_COMMAND	= $01;
       FIDO_ERR_INVALID_PARAMETER	= $02;
       FIDO_ERR_INVALID_LENGTH		= $03;
       FIDO_ERR_INVALID_SEQ		= $04;
       FIDO_ERR_TIMEOUT		= $05;
       FIDO_ERR_CHANNEL_BUSY		= $06;
       FIDO_ERR_LOCK_REQUIRED		= $0a;
       FIDO_ERR_INVALID_CHANNEL	= $0b;
       FIDO_ERR_CBOR_UNEXPECTED_TYPE	= $11;
       FIDO_ERR_INVALID_CBOR		= $12;
       FIDO_ERR_MISSING_PARAMETER	= $14;
       FIDO_ERR_LIMIT_EXCEEDED		= $15;
       FIDO_ERR_UNSUPPORTED_EXTENSION	= $16;
       FIDO_ERR_FP_DATABASE_FULL =	$17;
       FIDO_ERR_LARGEBLOB_STORAGE_FULL = $18;
       FIDO_ERR_CREDENTIAL_EXCLUDED	= $19;
       FIDO_ERR_PROCESSING		= $21;
       FIDO_ERR_INVALID_CREDENTIAL	= $22;
       FIDO_ERR_USER_ACTION_PENDING	= $23;
       FIDO_ERR_OPERATION_PENDING	= $24;
       FIDO_ERR_NO_OPERATIONS		= $25;
       FIDO_ERR_UNSUPPORTED_ALGORITHM	= $26;
       FIDO_ERR_OPERATION_DENIED	= $27;
       FIDO_ERR_KEY_STORE_FULL		= $28;
       FIDO_ERR_NOT_BUSY		= $29;
       FIDO_ERR_NO_OPERATION_PENDING	= $2a;
       FIDO_ERR_UNSUPPORTED_OPTION	= $2b;
       FIDO_ERR_INVALID_OPTION		= $2c;
       FIDO_ERR_KEEPALIVE_CANCEL	= $2d;
       FIDO_ERR_NO_CREDENTIALS		= $2e;
       FIDO_ERR_USER_ACTION_TIMEOUT	= $2f;
       FIDO_ERR_NOT_ALLOWED		= $30;
       FIDO_ERR_PIN_INVALID		= $31;
       FIDO_ERR_PIN_BLOCKED		= $32;
       FIDO_ERR_PIN_AUTH_INVALID	= $33;
       FIDO_ERR_PIN_AUTH_BLOCKED	= $34;
       FIDO_ERR_PIN_NOT_SET		= $35;
       FIDO_ERR_PIN_REQUIRED		= $36;
       FIDO_ERR_PIN_POLICY_VIOLATION	= $37;
       FIDO_ERR_PIN_TOKEN_EXPIRED	= $38;
       FIDO_ERR_REQUEST_TOO_LARGE	= $39;
       FIDO_ERR_ACTION_TIMEOUT		= $3a;
       FIDO_ERR_UP_REQUIRED		= $3b;
       FIDO_ERR_UV_BLOCKED	= $3c;
       FIDO_ERR_UV_INVALID	= $3f;
       FIDO_ERR_UNAUTHORIZED_PERM = $40;

       FIDO_ERR_ERR_OTHER		= $7f;
       FIDO_ERR_SPEC_LAST		= $df;

//  defined internally
       FIDO_OK	=	FIDO_ERR_SUCCESS;
       FIDO_ERR_TX	=	-1;
       FIDO_ERR_RX	=	-2;
       FIDO_ERR_RX_NOT_CBOR	=	-3;
       FIDO_ERR_RX_INVALID_CBOR =	-4;
       FIDO_ERR_INVALID_PARAM	=	-5;
       FIDO_ERR_INVALID_SIG	=	-6;
       FIDO_ERR_INVALID_ARGUMENT =	-7;
       FIDO_ERR_USER_PRESENCE_REQUIRED	= -8;
       FIDO_ERR_INTERNAL	=	-9;
       FIDO_ERR_NOTFOUND	=	-10;
       FIDO_ERR_COMPRESS = -11;



// const char *fido_strerr(int);
function fido_strerr( errCode : integer ) : PAnsiChar; cdecl; external libFido;


// from eddsa.h

function eddsa_pk_new : Peddsa_pk_t; cdecl; external libFido;
procedure eddsa_pk_free( var pkp : Peddsa_pk_t ); cdecl; external libFido;
function eddsa_pk_to_EVP_PKEY( pk : Peddsa_pk_t ) : PEVP_PKEY; cdecl; external libFido;

function eddsa_pk_from_EVP_PKEY( pk :  Peddsa_pk_t; pkey : PEVP_PKEY) : integer; cdecl; external libFido;
function eddsa_pk_from_ptr(pk : Peddsa_pk_t; ptr : Pointer; len : size_t) : integer; cdecl; external libFido;

// from es256.h
function es256_pk_new : Pes256_pk_t; cdecl; external libFido;
procedure es256_pk_free( var pkp : Pes256_pk_t ); cdecl; external libFido;
function es256_pk_to_EVP_PKEY( pk : Pes256_pk_t) : PEVP_PKEY; cdecl; external libFido;

function es256_pk_from_EC_KEY( pk :  Pes256_pk_t; pkey : PEVP_PKEY) : integer; cdecl; external libFido;
function es256_pk_from_EVP_PKEY(pk : Pes256_pk_t; pkey : PEVP_PKEY) : integer; cdecl; external libFido;
function es256_pk_from_ptr(pk : Pes256_pk_t; ptr : Pointer; len : size_t) : integer; cdecl; external libFido;

// from es384.h
function es384_pk_new : Pes384_pk_t; cdecl; external libFido;
procedure es384_pk_free(var pk : Pes384_pk_t); cdecl; external libFido;
function es384_pk_to_EVP_PKEY(pk : Pes384_pk_t) : PEVP_PKEY; cdecl; external libFido;

function es384_pk_from_EC_KEY(pk : Pes384_pk_t; pkey : PEC_KEY) : integer; cdecl; external libFido;
function es384_pk_from_EVP_PKEY(pk : Pes384_pk_t; pkey : PEVP_PKEY) : integer; cdecl; external libFido;
function es384_pk_from_ptr(pk : Pes384_pk_t; ptr : Pointer; len : size_t) : integer; cdecl; external libFido;


// from rs256.h
function rs256_pk_new : Prs256_pk_t; cdecl; external libFido;
procedure rs256_pk_free( var pkp : Prs256_pk_t ); cdecl; external libFido;
function rs256_pk_to_EVP_PKEY( pk : Prs256_pk_t ) : PEVP_PKEY; cdecl; external libFido;

function rs256_pk_from_EVP_PKEY(pk : Prs256_pk_t; pkey : PEVP_PKEY) : integer; cdecl; external libFido;
function rs256_pk_from_RSA( pk :  Prs256_pk_t; pkey : PEVP_PKEY) : integer; cdecl; external libFido;
function rs256_pk_from_ptr(pk : Prs256_pk_t; ptr : Pointer; len : size_t) : integer; cdecl; external libFido;

// ###########################################
// #### from fido.h
// ###########################################

function fido_assert_new : Pfido_assert_t; cdecl; external libFido;
function fido_cred_new : Pfido_cred_t; cdecl; external libFido;
function fido_dev_new : Pfido_dev_t; cdecl; external libFido;
function fido_dev_new_with_info( dev : Pfido_dev_info_t) : Pfido_dev_t; cdecl; external libFido;
function fido_dev_info_new(n : size_t) : Pfido_dev_info_t; cdecl; external libFido;
function fido_cbor_info_new : Pfido_cbor_info_t; cdecl; external libFido;
function fido_dev_io_handle( dev : Pfido_dev ) : Pointer; cdecl; external libFido;

procedure fido_assert_free( var assert_p : Pfido_assert_t); cdecl; external libFido;
procedure fido_cbor_info_free(var ci_p : Pfido_cbor_info_t); cdecl; external libFido;
procedure fido_cred_free(var cred_p : Pfido_cred_t); cdecl; external libFido;
procedure fido_dev_force_fido2(dev : Pfido_dev_t); cdecl; external libFido;
procedure fido_dev_force_u2f(dev : Pfido_dev_t); cdecl; external libFido;
procedure fido_dev_free(var dev_p : Pfido_dev_t); cdecl; external libFido;
procedure fido_dev_info_free(devlist_p : PPfido_dev_info_t; n : size_t); cdecl; external libFido;

const cFidoInitDefault = 0;
      cFidoInitDebug = 1;

procedure fido_init(flags : integer); cdecl; external libFido;
procedure fido_set_log_handler(log_handler : fido_log_handler_t); cdecl; external libFido;

function fido_assert_authdata_ptr(assert : Pfido_assert_t; idx : size_t) : PByte; cdecl; external libFido;

{$IFDEF FIDODLL_V1_15}
function fido_assert_authdata_raw_ptr(assert: Pfido_assert_t; idx : size_t) : PByte; cdecl; external libFido;
{$ENDIF}
function fido_assert_clientdata_hash_ptr(assert : Pfido_assert_t) : PByte; cdecl; external libFido;
function fido_assert_hmac_secret_ptr(assert : Pfido_assert_t; idx : size_t) : PByte; cdecl; external libFido;
function fido_assert_id_ptr(assert : Pfido_assert_t; idx : size_t) : PByte; cdecl; external libFido;
function fido_assert_largeblob_key_ptr(assert : Pfido_assert_t; idx : size_t) : PByte; cdecl; external libFido;
function fido_assert_sig_ptr(assert : Pfido_assert_t; idx : size_t) : PByte; cdecl; external libFido;
function fido_assert_user_id_ptr(assert : Pfido_assert_t; idx : size_t) : PByte; cdecl; external libFido;
function fido_assert_blob_ptr(assert : Pfido_assert_t; idx : size_t) : PByte; cdecl; external libFido;

function fido_cbor_info_certs_name_ptr( ci : Pfido_cbor_info_t ) : PPAnsiChar; cdecl; external libFido;
function fido_cbor_info_extensions_ptr(ci : Pfido_cbor_info_t) : PPAnsiChar; cdecl; external libFido;
function fido_cbor_info_options_name_ptr(ci : Pfido_cbor_info_t) : PPAnsiChar; cdecl; external libFido;
function fido_cbor_info_transports_ptr(ci : Pfido_cbor_info_t) : PPAnsiChar; cdecl; external libFido;
function fido_cbor_info_versions_ptr(ci : Pfido_cbor_info_t) : PPAnsiChar; cdecl; external libFido;
function fido_cbor_info_options_value_ptr(ci : Pfido_cbor_info_t) : PBoolean; cdecl; external libFido;
function fido_assert_rp_id(assert : Pfido_assert_t) : PAnsiChar; cdecl; external libFido;
function fido_assert_user_display_name(assert : Pfido_assert_t; idx : size_t) : PAnsiChar; cdecl; external libFido;
function fido_assert_user_icon(assert : Pfido_assert_t; idx : size_t) : PAnsiChar; cdecl; external libFido;
function fido_assert_user_name(assert : Pfido_assert_t; idx : size_t) : PAnsiChar; cdecl; external libFido;
function fido_cbor_info_algorithm_type(ci : Pfido_cbor_info_t; idx : size_t) : PAnsiChar; cdecl; external libFido;
function fido_cred_display_name(cred_p : Pfido_cred_t) : PAnsiChar; cdecl; external libFido;
function fido_cred_fmt(cred_p : Pfido_cred_t) : PAnsiChar; cdecl; external libFido;
function fido_cred_rp_id(cred_p : Pfido_cred_t) : PAnsiChar; cdecl; external libFido;
function fido_cred_rp_name(cred_p : Pfido_cred_t) : PAnsiChar; cdecl; external libFido;
function fido_cred_user_name(cred_p : Pfido_cred_t) : PAnsiChar; cdecl; external libFido;
function fido_dev_info_manufacturer_string(devlist : Pfido_dev_info_t) : PAnsiChar; cdecl; external libFido;
function fido_dev_info_path(devlist : Pfido_dev_info_t) : PAnsiChar; cdecl; external libFido;
function fido_dev_info_product_string(devList : Pfido_dev_info_t) : PAnsiChar; cdecl; external libFido;

function fido_dev_info_ptr(devList : Pfido_dev_info_t; n : size_t) : Pfido_dev_info_t; cdecl; external libFido;
function fido_cbor_info_protocols_ptr(ci : Pfido_cbor_info_t) : PByte; cdecl; external libFido;
function fido_cbor_info_certs_value_ptr(ci : Pfido_cbor_info_t) : PUInt64; cdecl; external libFido;
function fido_cbor_info_aaguid_ptr(ci : Pfido_cbor_info_t) : PByte; cdecl; external libFido;
function fido_cred_aaguid_ptr(ci : Pfido_cred_t) : PByte; cdecl; external libFido;
function fido_cred_attstmt_ptr(cred_p : Pfido_cred_t) : PByte; cdecl; external libFido;

function fido_cred_authdata_ptr(ci : Pfido_cred_t) : PByte; cdecl; external libFido;
function fido_cred_authdata_raw_ptr(ci : Pfido_cred_t) : PByte; cdecl; external libFido;
function fido_cred_clientdata_hash_ptr(ci : Pfido_cred_t) : PAnsiChar; cdecl; external libFido;
function fido_cred_id_ptr(ci : Pfido_cred_t) : PByte; cdecl; external libFido;
function fido_cred_aaguid_len(ci : Pfido_cred_t) : size_t; cdecl; external libFido;
function fido_cred_user_id_ptr(ci : Pfido_cred_t) : PByte; cdecl; external libFido;
function fido_cred_pubkey_ptr(ci : Pfido_cred_t) : PAnsiChar; cdecl; external libFido;
function fido_cred_sig_ptr(ci : Pfido_cred_t) : PByte; cdecl; external libFido;
function fido_cred_x5c_ptr(ci : Pfido_cred_t) : PByte; cdecl; external libFido;
{$IFDEF FIDODLL_V1_15}
function fido_cred_x5c_list_ptr(ci : Pfido_cred_t; idx : size_t) : PByte; cdecl; external libFido;
{$ENDIF}
function fido_cred_largeblob_key_ptr(ci : Pfido_cred_t) : PByte; cdecl; external libFido;
function fido_cred_pin_minlen(cred : Pfido_cred_t) : size_t; cdecl; external libFido;

function fido_assert_allow_cred(assert : Pfido_assert_t; ptr : PByte; len : size_t) : integer; cdecl; external libFido;
function fido_assert_empty_allow_list(assert : Pfido_assert_t) : integer; cdecl; external libFido;
function fido_assert_set_authdata(assert : Pfido_assert_t; idx : size_t; ptr : PByte; len : size_t) : integer; cdecl; external libFido;
function fido_assert_set_clientdata_hash(assert : Pfido_assert_t; ptr : PByte; len : size_t) : integer; cdecl; external libFido;
function fido_assert_set_count(assert : Pfido_assert_t; n : size_t) : integer; cdecl; external libFido;
function fido_assert_set_extensions(assert : Pfido_assert_t; flags : integer) : integer; cdecl; external libFido;
function fido_assert_set_hmac_salt(assert : Pfido_assert_t; ptr : PByte; len : size_t) : integer; cdecl; external libFido;
function fido_assert_set_hmac_secret(assert : Pfido_assert_t; idx : size_t; ptr : PByte; len : size_t) : integer; cdecl; external libFido;
//function fido_assert_set_options(assert : Pfido_assert_t; bool, bool) __attribute__((__deprecated__)) : integer;
function fido_assert_set_rp(assert : Pfido_assert_t; id : PAnsiChar) : integer; cdecl; external libFido;
function fido_assert_set_up(assert : Pfido_assert_t; up : fido_opt_t) : integer; cdecl; external libFido;
function fido_assert_set_uv(assert : Pfido_assert_t; uv : fido_opt_t) : integer; cdecl; external libFido;
function fido_assert_set_sig(assert : Pfido_assert_t; idx : size_t; ptr : PByte; len : size_t) : integer; cdecl; external libFido;
{$IFDEF FIDODLL_V1_15}
function fido_assert_set_winhello_appid(assert : Pfido_assert_t; id : PAnsiChar ) : integer; cdecl; external libFido;
{$ENDIF}
function fido_assert_verify(assert : Pfido_assert_t; idx : size_t; cose_alg : integer; pk : Pointer) : integer; cdecl; external libFido;
function fido_cbor_info_algorithm_cose(ci : Pfido_cbor_info_t; idx : size_t) : integer; cdecl; external libFido;
function fido_assert_set_authdata_raw(assert : Pfido_assert_t; idx : size_t; ptr : PByte; len : size_t) : integer; cdecl; external libFido;
function fido_assert_set_clientdata(assert : Pfido_assert_t; ptr : PAnsiChar; len : size_t): integer; cdecl; external libFido;
function fido_assert_sigcount(assert : Pfido_assert_t; idx : size_t): UInt32; cdecl; external libFido;

function fido_cred_empty_exclude_list(cred : Pfido_cred_t) : integer; cdecl; external libFido;
{$IFDEF FIDODLL_V1_16}
function fido_cred_entattest(cred : Pfido_cred_t) : boolean; cdecl; external libFido;
{$ENDIF}
function fido_cred_exclude(cred : Pfido_cred_t;  ptr : PByte; len : size_t) : integer; cdecl; external libFido;
function fido_cred_prot(cred : Pfido_cred_t) : integer; cdecl; external libFido;
function fido_cred_set_attstmt(cred : Pfido_cred_t; ptr : PByte; len : size_t) : integer; cdecl; external libFido;
{$IFDEF FIDODLL_V1_15}
function fido_cred_set_attobj(cred : Pfido_cred_t; ptr: PByte; len : size_t) : integer; cdecl; external libFido;
{$ENDIF}
function fido_cred_set_authdata(cred : Pfido_cred_t; ptr : PByte; len : size_t) : integer; cdecl; external libFido;
function fido_cred_set_clientdata_hash(cred : Pfido_cred_t; ptr : PByte; len : size_t) : integer; cdecl; external libFido;
{$IFDEF FIDODLL_V1_16}
function fido_cred_set_entattest(cred : Pfido_cred_t; ea : integer) : integer;  cdecl; external libFido;
{$ENDIF}
function fido_cred_set_extensions(cred : Pfido_cred_t; flags : integer) : integer; cdecl; external libFido;
function fido_cred_set_fmt(cred : Pfido_cred_t; ptr : PAnsiChar) : integer; cdecl; external libFido;
function fido_cred_set_id(cred : Pfido_cred_t; ptr : PAnsiChar; len : size_t) : integer; cdecl; external libFido;
// function fido_cred_set_options(cred : Pfido_cred_t; bool, bool) __attribute__((__deprecated__)) : integer;
function fido_cred_set_pin_minlen(ci : Pfido_cred_t; len : size_t) : integer; cdecl; external libFido;
function fido_cred_set_prot( cred : Pfido_cred_t; prot : integer) : integer; cdecl; external libFido;
function fido_cred_set_rk(cred : Pfido_cred_t; rk : fido_opt_t) : integer; cdecl; external libFido;
function fido_cred_set_rp(cred : Pfido_cred_t; rp : PAnsiChar; name : PAnsiChar) : integer; cdecl; external libFido;
function fido_cred_set_sig(cred : Pfido_cred_t; ptr : PByte; len : size_t) : integer; cdecl; external libFido;
function fido_cred_set_type(cred : Pfido_cred_t; cose_alg : integer) : integer; cdecl; external libFido;
function fido_cred_set_uv(cred : Pfido_cred_t; uv : fido_opt_t) : integer; cdecl; external libFido;
function fido_cred_type(cred : Pfido_cred_t) : integer; cdecl; external libFido;
function fido_cred_set_user(cred : Pfido_cred_t; user_id : PByte; user_id_len : size_t; name : PAnsiChar; display_name : PAnsiChar; icon : PAnsiChar ) : integer; cdecl; external libFido;
function fido_cred_set_x509(cred : Pfido_cred_t; ptr : PByte; len : size_t) : integer; cdecl; external libFido;
function fido_cred_set_authdata_raw(cred : Pfido_cred_t; ptr : PByte; len : size_t) : integer; cdecl; external libFido;
function fido_cred_set_blob(cred : Pfido_cred_t; data : PByte; len : size_t) : integer; cdecl; external libFido;
function fido_cred_set_clientdata(cred : Pfido_cred_t; ptr : PAnsiChar; len : size_t) : integer; cdecl; external libFido;

function fido_cred_verify(cred : Pfido_cred_t) : integer; cdecl; external libFido;
function fido_cred_verify_self( cred : Pfido_cred_t) : integer; cdecl; external libFido;

function fido_dev_close(dev : Pfido_dev_t) : integer; cdecl; external libFido;
function fido_dev_get_assert(dev : Pfido_dev_t; assert : Pfido_assert_t; pin : PAnsiChar) : integer; cdecl; external libFido;
function fido_dev_get_cbor_info(dev : Pfido_dev_t; ci : Pfido_cbor_info_t) : integer; cdecl; external libFido;
function fido_dev_get_retry_count(dev : Pfido_dev_t; var retries : Integer) : integer; cdecl; external libFido;
function fido_dev_get_uv_retry_count(dev : Pfido_dev_t; var retries : integer) : integer; cdecl; external libFido;
function fido_dev_get_touch_begin(dev : Pfido_dev_t) : integer; cdecl; external libFido;
function fido_dev_get_touch_status(dev : Pfido_dev_t; var touched : integer; waitMs : integer) : integer; cdecl; external libFido;
function fido_dev_info_manifest(devlist : Pfido_dev_info_t; ilen : size_t; var olen : Integer) : integer; cdecl; external libFido;
function fido_dev_info_set(devlist : Pfido_dev_info_t; i : size_t; path : PAnsiChar;
                           manufacturer : PAnsiChar; product : PAnsiChar; io : Pfido_dev_io_t; transport : Pfido_dev_transport_t ) : integer; cdecl; external libFido;

function fido_dev_make_cred(dev : Pfido_dev_t; cred : Pfido_cred_t; pin : PAnsiChar) : integer; cdecl; external libFido;
function fido_dev_open_with_info(dev : Pfido_dev_t ) : integer; cdecl; external libFido;
function fido_dev_open(dev : Pfido_dev_t; path : PAnsiChar) : integer; cdecl; external libFido;
function fido_dev_reset(dev : Pfido_dev_t) : integer; cdecl; external libFido;
function fido_dev_set_io_functions(dev : Pfido_dev_t; io : Pfido_dev_io_t) : integer; cdecl; external libFido;
function fido_dev_set_pin(dev : Pfido_dev_t; pin : PAnsiChar; oldPin : PAnsiChar) : integer; cdecl; external libFido;
function fido_dev_set_transport_functions(dev : Pfido_dev_t; transFun : Pfido_dev_transport_t) : integer; cdecl; external libFido;
function fido_dev_set_timeout(dev : Pfido_dev_t; ms : integer) : integer; cdecl; external libFido;
function fido_dev_set_sigmask(dev : Pfido_dev_t; sigmask : Pfido_sigset_t) : integer; cdecl; external libFido;
function fido_dev_cancel(dev : Pfido_dev_t) : integer; cdecl; external libFido;
function fido_dev_has_pin(dev : Pfido_dev_t) : boolean; cdecl; external libFido;
function fido_dev_has_uv(dev : Pfido_dev_t) : boolean; cdecl; external libFido;

function fido_dev_is_fido2(dev : Pfido_dev_t) : boolean; cdecl; external libFido;
function fido_dev_is_winhello(dev : Pfido_dev_t) : boolean; cdecl; external libFido;
function fido_dev_supports_pin(dev : Pfido_dev_t) : boolean; cdecl; external libFido;
function fido_dev_supports_cred_prot(dev : Pfido_dev_t) : boolean; cdecl; external libFido;
function fido_dev_supports_permissions(dev : Pfido_dev_t) : boolean; cdecl; external libFido;
function fido_dev_supports_credman(dev : Pfido_dev_t) : boolean; cdecl; external libFido;
function fido_dev_supports_uv(dev : Pfido_dev_t) : boolean; cdecl; external libFido;

function fido_dev_largeblob_get(dev : Pfido_dev_t; key_ptr : PByte; keyLen : size_t;
                                var blob_ptr : Pbyte; var blob_len : size_t) : integer; cdecl; external libFido;
function fido_dev_largeblob_set(dev : Pfido_dev_t; key_ptr : PByte; key_len : integer;
                                blob : PByte; blob_len : size_t; pin : PAnsiChar) : integer; cdecl; external libFido;
function fido_dev_largeblob_remove(dev : Pfido_dev_t; key_ptr : PByte; key_len : size_t; pin : PAnsiChar) : integer; cdecl; external libFido;
function fido_dev_largeblob_get_array(dev : Pfido_dev_t; var cbor_ptr : PByte; var cbor_len : size_t) : integer; cdecl; external libFido;
function fido_dev_largeblob_set_array(dev : Pfido_dev_t; cbor_ptr : PByte; cbor_len : size_t; pin : PAnsiChar) : Integer; cdecl; external libFido;

function fido_assert_authdata_len(assert : Pfido_assert_t; idx : size_t) : size_t; cdecl; external libFido;
{$IFDEF FIDODLL_V1_15}
function fido_assert_authdata_raw_len(assert : Pfido_assert_t; idx : size_t) : size_t; cdecl; external libFido;
{$ENDIF}

function fido_cred_authdata_raw_len(cred : Pfido_cred_t) : size_t; cdecl; external libFido;
function fido_assert_clientdata_hash_len(assert : Pfido_assert_t) : size_t; cdecl; external libFido;
function fido_assert_count(assert : Pfido_assert_t) : size_t; cdecl; external libFido;
function fido_assert_hmac_secret_len(assert : Pfido_assert_t; idx : size_t) : size_t; cdecl; external libFido;
function fido_assert_id_len(assert : Pfido_assert_t; idx : size_t) : size_t; cdecl;external libFido;
function fido_assert_largeblob_key_len(assert : Pfido_assert_t; idx : size_t) : size_t; cdecl; external libfido;
function fido_assert_sig_len(assert : Pfido_assert_t; idx : size_t) : size_t; cdecl; external libFido;
function fido_assert_user_id_len(assert : Pfido_assert_t; idx : size_t) : size_t; cdecl; external libFido;
function fido_assert_blob_len(assert : Pfido_assert_t; idx : size_t) : size_t; cdecl; external libFido;

function fido_cbor_info_aaguid_len(ci : Pfido_cbor_info_t) : size_t; cdecl; external libFido;
function fido_cbor_info_algorithm_count(ci : Pfido_cbor_info_t) : size_t; cdecl; external libFido;
function fido_cbor_info_certs_len(ci : Pfido_cbor_info_t) : size_t; cdecl; external libFido;
function fido_cbor_info_extensions_len(ci : Pfido_cbor_info_t) : size_t;cdecl; external libFido;
function fido_cbor_info_options_len(ci : Pfido_cbor_info_t) : size_t;cdecl; external libFido;
function fido_cbor_info_protocols_len(ci : Pfido_cbor_info_t) : size_t;cdecl; external libFido;
function fido_cbor_info_transports_len(ci : Pfido_cbor_info_t) : size_t;cdecl; external libFido;
function fido_cbor_info_versions_len(ci : Pfido_cbor_info_t) : size_t;cdecl; external libFido;

function fido_cred_attstmt_len(ci : Pfido_cred_t) : size_t; cdecl; external libFido;
function fido_cred_authdata_len(cred : Pfido_cred_t) : size_t;cdecl; external libFido;
function fido_cred_clientdata_hash_len(cred : Pfido_cred_t) : size_t;cdecl; external libFido;
function fido_cred_id_len(cred : Pfido_cred_t) : size_t;cdecl; external libFido;
function fido_cred_user_id_len(cred : Pfido_cred_t) : size_t;cdecl; external libFido;
function fido_cred_pubkey_len(cred : Pfido_cred_t) : size_t;cdecl; external libFido;
function fido_cred_sig_len(cred : Pfido_cred_t) : size_t; cdecl; external libFido;
function fido_cred_x5c_len(cred : Pfido_cred_t) : size_t; cdecl; external libFido;

{$IFDEF FIDODLL_V1_15}
function fido_cred_x5c_list_count(cred : Pfido_cred_t) : size_t; cdecl; external libFido;
function fido_cred_x5c_list_len(cred : Pfido_cred_t; idx : size_t) : size_t; cdecl; external libFido;
{$ENDIF}

function fido_cred_largeblob_key_len(cred : Pfido_cred_t) : size_t; cdecl; external libFido;

function fido_assert_flags(assert : Pfido_assert_t; flags : size_t) : Byte; cdecl; external libFido;
function fido_cred_flags(cred : Pfido_cred_t) : Byte; cdecl; external libFido;
function fido_cred_sigcount(cred : Pfido_cred_t) : Longword; cdecl; external libFido;
function fido_dev_protocol(dev : Pfido_dev_t) : Byte; cdecl; external libFido;
function fido_dev_major(dev : Pfido_dev_t) : Byte; cdecl; external libFido;
function fido_dev_minor(dev : Pfido_dev_t) : Byte; cdecl; external libFido;
function fido_dev_build(dev : Pfido_dev_t) : Byte; cdecl; external libFido;
function fido_dev_flags(dev : Pfido_dev_t) : Byte; cdecl; external libFido;
function fido_dev_info_vendor(di : Pfido_dev_info_t) : smallInt; cdecl; external libFido;
function fido_dev_info_product(di : Pfido_dev_info_t) : smallInt; cdecl; external libFido;
function fido_cbor_info_maxmsgsiz(ci : Pfido_cbor_info_t) : UInt64; cdecl; external libFido;
function fido_cbor_info_maxlargeblob(ci : Pfido_cbor_info_t) : UInt64; cdecl; external libFido;
function fido_cbor_info_fwversion(ci : Pfido_cbor_info_t) : UINT64; cdecl; external libFido;
function fido_cbor_info_maxcredcntlst(ci : Pfido_cbor_info_t) : UInt64; cdecl; external libFido;
function fido_cbor_info_maxcredidlen(ci : Pfido_cbor_info_t) : UINT64; cdecl; external libFido;
function fido_cbor_info_minpinlen(ci : Pfido_cbor_info_t) : UINT64; cdecl; external libFido;
function fido_cbor_info_maxcredbloblen(ci : Pfido_cbor_info_t) : UINT64; cdecl; external libFido;
function fido_cbor_info_maxrpid_minpinlen(ci : Pfido_cbor_info_t) : UINT64; cdecl; external libFido;
function fido_cbor_info_uv_attempts(ci : Pfido_cbor_info_t) : UINT64; cdecl; external libFido;
function fido_cbor_info_uv_modality(ci : Pfido_cbor_info_t) : UINT64; cdecl; external libFido;
function fido_cbor_info_rk_remaining(ci : Pfido_cbor_info_t) : INT64; cdecl; external libFido;
function fido_cbor_info_new_pin_required(ci : Pfido_cbor_info_t) : Boolean; cdecl; external libFido;

// ###########################################
// #### from config.h
// ###########################################

function fido_dev_enable_entattest(dev : Pfido_dev_t; pin : PAnsiChar) : integer; cdecl; external libFido;
function fido_dev_force_pin_change(dev : Pfido_dev_t; pin : PAnsiChar) : integer; cdecl; external libFido;
function fido_dev_toggle_always_uv(dev : Pfido_dev_t; pin : PAnsiChar) : integer; cdecl; external libFido;
function fido_dev_set_pin_minlen(dev : Pfido_dev_t; len : size_t; pin : PAnsiChar) : integer; cdecl; external libFido;
function fido_dev_set_pin_minlen_rpid(dev : Pfido_dev_t; rpid : PAnsiChar; n : size_t; pin : PAnsiChar) : integer; cdecl; external libFido;

// ###########################################
// #### from bio.h
// ###########################################

type
  fido_bio_template_t = packed record
    id : fido_blob_t;
    name : PAnsiChar;
  end;
  Pfido_bio_template_t = ^fido_bio_template_t;

  fido_bio_template_array = packed record
     ptr : Pfido_bio_template_t;
     n_alloc : size_t;          // number of allocated entries
     n_rx : size_t;             // number of populated entries
  end;
  fido_bio_template_array_t = fido_bio_template_array;

  fido_bio_enroll = packed record
    remaining_samples : UInt8;
    last_status : UInt8;
    token : Pfido_blob_t;
  end;
  fido_bio_enroll_t = fido_bio_enroll;

  fido_bio_info = packed record
     typ : UInt8;
     max_samples : UInt8;
  end;
  fido_bio_info_t = fido_bio_info;
  Pfido_bio_info_t = ^fido_bio_info_t;

  Pfido_bio_template_array_t = pointer;
  Pfido_bio_enroll_t = Pointer;


const FIDO_BIO_ENROLL_FP_GOOD				 = $00;
      FIDO_BIO_ENROLL_FP_TOO_HIGH			 = $01;
      FIDO_BIO_ENROLL_FP_TOO_LOW			 = $02;
      FIDO_BIO_ENROLL_FP_TOO_LEFT			 = $03;
      FIDO_BIO_ENROLL_FP_TOO_RIGHT			 = $04;
      FIDO_BIO_ENROLL_FP_TOO_FAST			 = $05;
      FIDO_BIO_ENROLL_FP_TOO_SLOW			 = $06;
      FIDO_BIO_ENROLL_FP_POOR_QUALITY			 = $07;
      FIDO_BIO_ENROLL_FP_TOO_SKEWED			 = $08;
      FIDO_BIO_ENROLL_FP_TOO_SHORT			 = $09;
      FIDO_BIO_ENROLL_FP_MERGE_FAILURE		 = $0a;
      FIDO_BIO_ENROLL_FP_EXISTS			 = $0b;
      FIDO_BIO_ENROLL_FP_DATABASE_FULL		 = $0c;
      FIDO_BIO_ENROLL_NO_USER_ACTIVITY		 = $0d;
      FIDO_BIO_ENROLL_NO_USER_PRESENCE_TRANSITION	 = $0e;

function fido_bio_template_name(template : Pfido_bio_template_t) : PAnsiChar; cdecl; external libFido;
function fido_bio_template(templateArray : Pfido_bio_template_array_t; idx : size_t ): Pfido_bio_template_t; cdecl; external libFido;
function fido_bio_template_id_ptr(template : Pfido_bio_template_t) : PByte; cdecl; external libFido;
function fido_bio_enroll_new : Pfido_bio_enroll_t; cdecl; external libFido;
function fido_bio_info_new : Pfido_bio_info_t; cdecl; external libFido;
function fido_bio_template_array_new : Pfido_bio_template_array_t; cdecl; external libFido;
function fido_bio_template_new : Pfido_bio_template_t; cdecl; external libFido;
function fido_bio_dev_enroll_begin(dev : Pfido_dev_t; template : Pfido_bio_template_t;
    endroll : Pfido_bio_enroll_t; timeout : UInt32; pin : PAnsiChar) : integer;  cdecl; external libFido;
function fido_bio_dev_enroll_cancel(dev : Pfido_dev_t) : integer;  cdecl; external libFido;
function fido_bio_dev_enroll_continue(dev : Pfido_dev_t; template : Pfido_bio_template_t;
    enroll : Pfido_bio_enroll_t; timeout : uint32) : integer;  cdecl; external libFido;
function fido_bio_dev_enroll_remove(dev : Pfido_dev_t; template : Pfido_bio_template_t;
    pin : PAnsiChar) : integer;  cdecl; external libFido;
function fido_bio_dev_get_info(dev : Pfido_dev_t; info : Pfido_bio_info_t) : integer;  cdecl; external libFido;
function fido_bio_dev_get_template_array(dev : Pfido_dev_t; templateArray : Pfido_bio_template_array_t;
    pin : PAnsiChar) : integer;  cdecl; external libFido;
function fido_bio_dev_set_template_name(dev : Pfido_dev_t; template : Pfido_bio_template_t;
    pin : PAnsiChar) : integer;  cdecl; external libFido;
function fido_bio_template_set_id(template : Pfido_bio_template_t; ptr : PByte; len : size_t) : integer;  cdecl; external libFido;
function fido_bio_template_set_name(template : Pfido_bio_template_t; name : PAnsiChar) : integer;  cdecl; external libFido;
function fido_bio_template_array_count(template_array : Pfido_bio_template_array_t) : size_t;  cdecl; external libFido;
function fido_bio_template_id_len(template : Pfido_bio_template_t) : size_t;  cdecl; external libFido;
function fido_bio_enroll_last_status(enroll : Pfido_bio_enroll_t) : byte;  cdecl; external libFido;
function fido_bio_enroll_remaining_samples(enroll : Pfido_bio_enroll_t) : byte;  cdecl; external libFido;
function fido_bio_info_max_samples(info : Pfido_bio_info_t) : Byte;  cdecl; external libFido;
function fido_bio_info_type(info : Pfido_bio_info_t) : Byte;  cdecl; external libFido;
procedure fido_bio_enroll_free(var  enroll : Pfido_bio_enroll_t);  cdecl; external libFido;
procedure fido_bio_info_free(var info : Pfido_bio_info_t);  cdecl; external libFido;
procedure fido_bio_template_array_free(var template_array : Pfido_bio_template_array_t);  cdecl; external libFido;
procedure fido_bio_template_free(var template : Pfido_bio_template_t);  cdecl; external libFido;



// ###########################################
// #### from credman.h
// ###########################################


function fido_credman_rp_id(rp : Pfido_credman_rp_t; idx : size_t) : PAnsiChar; cdecl; external libFido;
function fido_credman_rp_name(rp : Pfido_credman_rp_t; idx : size_t) : PAnsiChar; cdecl; external libFido;

function fido_credman_rk(rk : Pfido_credman_rk_t; idx : size_t) : Pfido_cred_t; cdecl; external libFido;


function fido_credman_metadata_new : Pfido_credman_metadata_t; cdecl; external libFido;
function fido_credman_rk_new : Pfido_credman_rk_t; cdecl; external libFido;
function fido_credman_rp_new : Pfido_credman_rp_t; cdecl; external libFido;

function fido_credman_del_dev_rk(dev : Pfido_dev_t; cred_id : PByte; cred_id_len : size_t; pin : PAnsiChar) : integer; cdecl; external libFido;
function fido_credman_get_dev_metadata(dev : Pfido_dev_t; metaData : Pfido_credman_metadata_t; pin : PAnsiChar) : integer; cdecl; external libFido;
function fido_credman_get_dev_rk(dev : Pfido_dev_t; rp_id : PAnsiChar; rk : Pfido_credman_rk_t; pin : PAnsiChar) : integer; cdecl; external libFido;
function fido_credman_set_dev_rk(dev : Pfido_dev_t; cred : Pfido_cred_t; pin : PAnsiChar) : integer; cdecl; external libFido;
function fido_credman_get_dev_rp(dev : Pfido_dev_t; rp : Pfido_credman_rp_t; pin : PAnsiChar) : integer; cdecl; external libFido;

function fido_credman_rk_count(rk : Pfido_credman_rk_t) : size_t; cdecl; external libFido;
function fido_credman_rp_count(rp : Pfido_credman_rp_t) : size_t; cdecl; external libFido;
function fido_credman_rp_id_hash_len(rp : Pfido_credman_rp_t; idx : size_t) : size_t; cdecl; external libFido;
function fido_credman_rp_id_hash_ptr(rp : Pfido_credman_rp_t; idx : size_t) : PByte; cdecl; external libFido;

function fido_credman_rk_existing(metadata : Pfido_credman_metadata_t) : UINT64; cdecl; external libFido;
function fido_credman_rk_remaining(metadata : Pfido_credman_metadata_t) : UINT64; cdecl; external libFido;

procedure fido_credman_metadata_free(var metadata_p : Pfido_credman_metadata_t); cdecl; external libFido;
procedure fido_credman_rk_free(var rk_p : Pfido_credman_rk_t); cdecl; external libFido;
procedure fido_credman_rp_free(var rp_p : Pfido_credman_rp_t); cdecl; external libFido;

implementation

end.
