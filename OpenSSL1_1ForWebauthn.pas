unit OpenSSL1_1ForWebauthn;

// ###########################################
// #### Imports needed from Openssl 1.1 for Webauthn support
// #### subset taken from: https://github.com/grijjy/DelphiOpenSsl
// ###########################################

{$MINENUMSIZE 4}

interface

uses SysUtils, Types;

// this unit is a stripped down version of OpenSSL.api_11 from Grijjy
const
  {$IF Defined(WIN32)}
  LIB_CRYPTO = 'libcrypto-1_1.dll';
  LIB_SSL = 'libssl-1_1.dll';
  _PU = '';
  {$ELSEIF Defined(WIN64)}
  LIB_CRYPTO = 'libcrypto-1_1-x64.dll';
  LIB_SSL = 'libssl-1_1-x64.dll';
  _PU = '';
  {$ELSEIF Defined(ANDROID64)}
  LIB_CRYPTO = 'libcrypto-android64.a';
  LIB_SSL = 'libssl-android64.a';
  _PU = '';
  {$ELSEIF Defined(ANDROID32)}
  LIB_CRYPTO = 'libcrypto-android32.a';
  LIB_SSL = 'libssl-android32.a';
  _PU = '';
  {$ELSEIF Defined(IOS)}
  LIB_CRYPTO = 'libcrypto-ios.a';
  LIB_SSL = 'libssl-ios.a';
  _PU = '';
  {$ELSEIF Defined(MACOS32)}
  LIB_CRYPTO = 'libssl-merged-osx32.dylib'; { We unify LibSsl and LibCrypto into a common shared library on macOS }
  LIB_SSL = 'libssl-merged-osx32.dylib';
  _PU = '_';
  {$ELSEIF Defined(MACOS64)}
  LIB_CRYPTO = 'libcrypto-osx64.a';
  LIB_SSL = 'libssl-osx64.a';
  _PU = '';
  {$ELSEIF Defined(LINUX)}
  LIB_CRYPTO = 'libcrypto.so';
  LIB_SSL = 'libssl.so';
  _PU = '';
  {$ELSE}
    {$MESSAGE Error 'Unsupported platform'}
  {$IFEND}

const
  NID_X9_62_prime256v1 = 415;
  NID_sha256 = 672;

type
  PEVP_MD_CTX = Pointer;
  PEVP_MD = Pointer;
  PENGINE = Pointer;

  PECDSA_SIG = Pointer;
  PEC_GROUP = Pointer;
  PEC_POINT = Pointer;
  PBN_CTX = Pointer;
  PBIGNUM = Pointer;
  PEC_KEY = Pointer;
  PPECDSA_SIG = ^PECDSA_SIG;

  PPByte = ^PByte;
  PRSA = Pointer;

  {$IF CompilerVersion < 23.0}
  PUTF8Char = PAnsiChar;
  {$IFEND}



  (** Enum for the point conversion form as defined in X9.62 (ECDSA)
   *  for the encoding of a elliptic curve point (x,y) *)
  point_conversion_form_t = (
    (** the point is encoded as z||x, where the octet z specifies
     *  which solution of the quadratic equation y is  *)
    POINT_CONVERSION_COMPRESSED = 2,
    (** the point is encoded as z||x||y, where z is the octet 0x04  *)
    POINT_CONVERSION_UNCOMPRESSED = 4,
    (** the point is encoded as z||x||y, where the octet z specifies
     *  which solution of the quadratic equation y is  *)
    POINT_CONVERSION_HYBRID = 6);
  //Ppoint_conversion_form_t = ^point_conversion_form_t;


// hash functions
function EVP_get_digestbyname(name: PUTF8Char): PEVP_MD; cdecl; external LIB_CRYPTO name _PU + 'EVP_get_digestbyname';
function EVP_MD_CTX_create(): PEVP_MD_CTX; cdecl; external LIB_CRYPTO name _PU + 'EVP_MD_CTX_new';
function EVP_MD_CTX_new: Pointer; cdecl; external LIB_CRYPTO;
procedure EVP_MD_CTX_free(ctx: Pointer); cdecl; external LIB_CRYPTO;
function EVP_DigestInit(ctx: Pointer; const md: Pointer): Integer; cdecl; external LIB_CRYPTO;
function EVP_DigestUpdate(ctx: Pointer; const d: Pointer; cnt: LongWord): Integer; cdecl; external LIB_CRYPTO;
function EVP_DigestFinal(ctx: Pointer; md: Pointer; s: PCardinal): Integer; cdecl; external LIB_CRYPTO;
function EVP_DigestInit_ex(ctx: PEVP_MD_CTX; &type: PEVP_MD; impl: PENGINE): Integer; cdecl; external LIB_CRYPTO name _PU + 'EVP_DigestInit_ex';
function EVP_MD_size(md: PEVP_MD): Integer; cdecl; external LIB_CRYPTO name _PU + 'EVP_MD_size';
function EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: PByte; s: PCardinal): Integer; cdecl; external LIB_CRYPTO name _PU + 'EVP_DigestFinal_ex';

// bignum
function BN_CTX_new(): PBN_CTX; cdecl; external LIB_CRYPTO name _PU + 'BN_CTX_new';
procedure BN_CTX_free(c: PBN_CTX); cdecl; external LIB_CRYPTO name _PU + 'BN_CTX_free';
function BN_bin2bn(s: Pointer; len: Integer; ret: PBIGNUM): PBIGNUM; cdecl; external LIB_CRYPTO name _PU + 'BN_bin2bn';
procedure BN_free(a: PBIGNUM); cdecl; external LIB_CRYPTO name _PU + 'BN_free';


// elliptic curve/ECDSA
function EC_KEY_new_by_curve_name(nid: Integer): PEC_KEY; cdecl; external LIB_CRYPTO name _PU + 'EC_KEY_new_by_curve_name';
procedure EC_KEY_free(key: PEC_KEY); cdecl; external LIB_CRYPTO name _PU + 'EC_KEY_free';
function EC_KEY_get0_group(key: PEC_KEY): PEC_GROUP; cdecl; external LIB_CRYPTO name _PU + 'EC_KEY_get0_group';
function EC_POINT_new(group: PEC_GROUP): PEC_POINT; cdecl; external LIB_CRYPTO name _PU + 'EC_POINT_new';
procedure EC_POINT_free(point: PEC_POINT); cdecl; external LIB_CRYPTO name _PU + 'EC_POINT_free';
function EC_POINT_set_affine_coordinates_GFp(group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): Integer; cdecl; external LIB_CRYPTO name _PU + 'EC_POINT_set_affine_coordinates_GFp';
function EC_KEY_set_public_key(key: PEC_KEY; pub: PEC_POINT): Integer; cdecl; external LIB_CRYPTO name _PU + 'EC_KEY_set_public_key';
function d2i_ECDSA_SIG(sig: PPECDSA_SIG; pp: PPByte; len: Integer): PECDSA_SIG; cdecl; external LIB_CRYPTO name _PU + 'd2i_ECDSA_SIG';
function ECDSA_do_verify(dgst: PByte; dgst_len: Integer; sig: PECDSA_SIG; eckey: PEC_KEY): Integer; cdecl; external LIB_CRYPTO name _PU + 'ECDSA_do_verify';
procedure ECDSA_SIG_free(sig: PECDSA_SIG); cdecl; external LIB_CRYPTO name _PU + 'ECDSA_SIG_free';
procedure EC_KEY_set_conv_form(eckey: PEC_KEY; cform: point_conversion_form_t); cdecl; external LIB_CRYPTO name _PU + 'EC_KEY_set_conv_form';
function EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): Integer; cdecl; external LIB_CRYPTO name _PU + 'EC_KEY_set_public_key_affine_coordinates';

function ECDSA_verify(&type: Integer; dgst: PByte; dgstlen: Integer; sig: PByte; siglen: Integer; eckey: PEC_KEY): Integer; cdecl; external LIB_CRYPTO name _PU + 'ECDSA_verify';

// rsa
function RSA_new: PRSA; cdecl; external LIB_CRYPTO name _PU + 'RSA_new';
function RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): Integer; cdecl; external LIB_CRYPTO name _PU + 'RSA_set0_key';
function RSA_verify(&type: Integer; m: PByte; m_length: Cardinal; sigbuf: PByte; siglen: Cardinal; rsa: PRSA): Integer; cdecl; external LIB_CRYPTO name _PU + 'RSA_verify';
procedure RSA_free(r: PRSA); cdecl; external LIB_CRYPTO name _PU + 'RSA_free';

// misc
function ERR_get_error(): Cardinal; cdecl; external LIB_CRYPTO name _PU + 'ERR_get_error';
implementation

end.
