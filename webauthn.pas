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

unit webauthn;

// conversion of the Webauthn.h file
// from https://github.com/microsoft/webauthn/blob/master/webauthn.h

interface

uses Types, Windows;

type
  PCWSTR = PWideChar;
  PVOID = Pointer;

const cWebAuthLibName = 'webauthn.dll';
//+------------------------------------------------------------------------------------------
// API Version Information.
// Caller should check for WebAuthNGetApiVersionNumber to check the presence of relevant APIs
// and features for their usage.
//-------------------------------------------------------------------------------------------

const WEBAUTHN_API_VERSION_1 = 1;
// WEBAUTHN_API_VERSION_1 : Baseline Version
//      Data Structures and their sub versions:
//          - WEBAUTHN_RP_ENTITY_INFORMATION                    :   1
//          - WEBAUTHN_USER_ENTITY_INFORMATION                  :   1
//          - WEBAUTHN_CLIENT_DATA                              :   1
//          - WEBAUTHN_COSE_CREDENTIAL_PARAMETER                :   1
//          - WEBAUTHN_COSE_CREDENTIAL_PARAMETERS               :   Not Applicable
//          - WEBAUTHN_CREDENTIAL                               :   1
//          - WEBAUTHN_CREDENTIALS                              :   Not Applicable
//          - WEBAUTHN_CREDENTIAL_EX                            :   1
//          - WEBAUTHN_CREDENTIAL_LIST                          :   Not Applicable
//          - WEBAUTHN_EXTENSION                                :   Not Applicable
//          - WEBAUTHN_EXTENSIONS                               :   Not Applicable
//          - WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS    :   3
//          - WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS      :   4
//          - WEBAUTHN_COMMON_ATTESTATION                       :   1
//          - WEBAUTHN_CREDENTIAL_ATTESTATION                   :   3
//          - WEBAUTHN_ASSERTION                                :   1
//      Extensions:
//          - WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET
//      APIs:
//          - WebAuthNGetApiVersionNumber
//          - WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable
//          - WebAuthNAuthenticatorMakeCredential
//          - WebAuthNAuthenticatorGetAssertion
//          - WebAuthNFreeCredentialAttestation
//          - WebAuthNFreeAssertion
//          - WebAuthNGetCancellationId
//          - WebAuthNCancelCurrentOperation
//          - WebAuthNGetErrorName
//          - WebAuthNGetW3CExceptionDOMError

            WEBAUTHN_API_VERSION_2 = 2;
// WEBAUTHN_API_VERSION_2 : Delta From WEBAUTHN_API_VERSION_1
//      Added Extensions:
//          - WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT
//

            WEBAUTHN_API_VERSION_3 = 3;
// WEBAUTHN_API_VERSION_3 : Delta From WEBAUTHN_API_VERSION_2
//      Data Structures and their sub versions:
//          - WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS    :   4
//          - WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS      :   5
//          - WEBAUTHN_CREDENTIAL_ATTESTATION                   :   4
//          - WEBAUTHN_ASSERTION                                :   2
//      Added Extensions:
//          - WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB
//          - WEBAUTHN_EXTENSIONS_IDENTIFIER_MIN_PIN_LENGTH
//

            WEBAUTHN_API_VERSION_4 = 4;
// WEBAUTHN_API_VERSION_4 : Delta From WEBAUTHN_API_VERSION_3
//      Data Structures and their sub versions:
//          - WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS    :   5
//          - WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS      :   6
//          - WEBAUTHN_ASSERTION                                :   3
//      APIs:
//          - WebAuthNGetPlatformCredentialList
//          - WebAuthNFreePlatformCredentialList
//          - WebAuthNDeletePlatformCredential
//

            WEBAUTHN_API_CURRENT_VERSION = WEBAUTHN_API_VERSION_2;
//+------------------------------------------------------------------------------------------
// Information about an RP Entity
//-------------------------------------------------------------------------------------------

            WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION = 1;

type
  _WEBAUTHN_RP_ENTITY_INFORMATION = packed record
     // Version of this structure, to allow for modifications in the future.
     // This field is required and should be set to CURRENT_VERSION above.
     dwVersion : DWORD;

     // Identifier for the RP. This field is required.
     pwszId : PCWSTR;

     // Contains the friendly name of the Relying Party, such as "Acme Corporation", "Widgets Inc" or "Awesome Site".
     // This field is required.
     pwszName : PCWSTR;

     // Optional URL pointing to RP's logo. 
     pwszIcon : PCWSTR;
  end;
  WEBAUTHN_RP_ENTITY_INFORMATION = _WEBAUTHN_RP_ENTITY_INFORMATION;
  TWebAuthnRPEntityInformation = WEBAUTHN_RP_ENTITY_INFORMATION;
  PWebAuthnRPEntityInformation = ^TWebAuthnRPEntityInformation;


// typedef const WEBAUTHN_RP_ENTITY_INFORMATION *PCWEBAUTHN_RP_ENTITY_INFORMATION;

//+------------------------------------------------------------------------------------------
// Information about an User Entity
//-------------------------------------------------------------------------------------------
const WEBAUTHN_MAX_USER_ID_LENGTH = 64;
      WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION = 1;

type
  _WEBAUTHN_USER_ENTITY_INFORMATION = packed record
    // Version of this structure, to allow for modifications in the future.
    // This field is required and should be set to CURRENT_VERSION above.
    dwVersion : DWORD;

    // Identifier for the User. This field is required.
    cbId : DWORD;
    // _Field_size_bytes_(cbId)
    pbId : PBYTE;

    // Contains a detailed name for this account, such as "john.p.smith@example.com".
    pwszName : PCWSTR;

    // Optional URL that can be used to retrieve an image containing the user's current avatar,
    // or a data URI that contains the image data.
    pwszIcon : PCWSTR;

    // For User: Contains the friendly name associated with the user account by the Relying Party, such as "John P. Smith".
    pwszDisplayName : PCWSTR;
  end;
  WEBAUTHN_USER_ENTITY_INFORMATION = _WEBAUTHN_USER_ENTITY_INFORMATION;
  TWebAuthUserEntityInformation = WEBAUTHN_USER_ENTITY_INFORMATION;
  PWebAuthUserEntityInformation = ^TWebAuthUserEntityInformation;
  PCWebAuthUserEntityInformation = PWebAuthUserEntityInformation;
//typedef const WEBAUTHN_USER_ENTITY_INFORMATION *PCWEBAUTHN_USER_ENTITY_INFORMATION;

//+------------------------------------------------------------------------------------------
// Information about client data.
//-------------------------------------------------------------------------------------------

const WEBAUTHN_HASH_ALGORITHM_SHA_256 = 'SHA-256';
      WEBAUTHN_HASH_ALGORITHM_SHA_384 = 'SHA-384';
      WEBAUTHN_HASH_ALGORITHM_SHA_512 = 'SHA-512';

      WEBAUTHN_CLIENT_DATA_CURRENT_VERSION = 1;

type
  _WEBAUTHN_CLIENT_DATA = packed record
    // Version of this structure, to allow for modifications in the future.
    // This field is required and should be set to CURRENT_VERSION above.
    dwVersion : DWORD;

    // Size of the pbClientDataJSON field.
    cbClientDataJSON : DWORD;
    // UTF-8 encoded JSON serialization of the client data.
    // _Field_size_bytes_(cbClientDataJSON)
    pbClientDataJSON : PAnsiChar;

    // Hash algorithm ID used to hash the pbClientDataJSON field.
    pwszHashAlgId : LPCWSTR;
  end;
  WEBAUTHN_CLIENT_DATA = _WEBAUTHN_CLIENT_DATA;
  TWebAuthnClientData = WEBAUTHN_CLIENT_DATA;
  PWebAuthnClientData = ^TWebAuthnClientData;
  PCWebAuthnClientData = PWebAuthnClientData;
//typedef const WEBAUTHN_CLIENT_DATA *PCWEBAUTHN_CLIENT_DATA;

//+------------------------------------------------------------------------------------------
// Information about credential parameters.
//-------------------------------------------------------------------------------------------

const WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY = 'public-key';

      WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 = -7;
      WEBAUTHN_COSE_ALGORITHM_ECDSA_P384_WITH_SHA384 = -35;
      WEBAUTHN_COSE_ALGORITHM_ECDSA_P521_WITH_SHA512 = -36;

      WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256 = -257;
      WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA384 = -258;
      WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA512 = -259;

      WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA256 = -37;
      WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA384 = -38;
      WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA512 = -39;

      WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION = 1;

type
  _WEBAUTHN_COSE_CREDENTIAL_PARAMETER = packed record
    // Version of this structure, to allow for modifications in the future.
    dwVersion : DWORD;

    // Well-known credential type specifying a credential to create.
    pwszCredentialType : LPCWSTR;

    // Well-known COSE algorithm specifying the algorithm to use for the credential.
    lAlg : LongInt;
  end;
  WEBAUTHN_COSE_CREDENTIAL_PARAMETER = _WEBAUTHN_COSE_CREDENTIAL_PARAMETER;
  PWEBAUTHN_COSE_CREDENTIAL_PARAMETER = ^WEBAUTHN_COSE_CREDENTIAL_PARAMETER;

type
  _WEBAUTHN_COSE_CREDENTIAL_PARAMETERS = packed record
    cCredentialParameters : DWORD;
    //_Field_size_(cCredentialParameters)
    pCredentialParameters : PWEBAUTHN_COSE_CREDENTIAL_PARAMETER;
  end;
  WEBAUTHN_COSE_CREDENTIAL_PARAMETERS = _WEBAUTHN_COSE_CREDENTIAL_PARAMETERS;
  TWebauthnCoseCredentialParameters = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS;
  PWEBAUTHN_COSE_CREDENTIAL_PARAMETERS = ^WEBAUTHN_COSE_CREDENTIAL_PARAMETERS;
  PCWEBAUTHN_COSE_CREDENTIAL_PARAMETERS = PWEBAUTHN_COSE_CREDENTIAL_PARAMETERS;

//+------------------------------------------------------------------------------------------
// Information about credential.
//-------------------------------------------------------------------------------------------
const WEBAUTHN_CREDENTIAL_CURRENT_VERSION = 1;

type
  _WEBAUTHN_CREDENTIAL = packed record
    // Version of this structure, to allow for modifications in the future.
    dwVersion : DWORD;

    // Size of pbID.
    cbId : DWORD;
    // Unique ID for this particular credential.
//    _Field_size_bytes_(cbId)
    pbId : PBYTE;

    // Well-known credential type specifying what this particular credential is.
    pwszCredentialType : LPCWSTR;
  end;
  WEBAUTHN_CREDENTIAL = _WEBAUTHN_CREDENTIAL;
  TWebAuthNCredential = WEBAUTHN_CREDENTIAL;
  PWEBAUTHN_CREDENTIAL = ^WEBAUTHN_CREDENTIAL;
  PWebAuthNCredential = PWEBAUTHN_CREDENTIAL;

type
  _WEBAUTHN_CREDENTIALS = packed record
    cCredentials : DWORD;
//    _Field_size_(cCredentials)
    pCredentials : PWEBAUTHN_CREDENTIAL;
  end;
  WEBAUTHN_CREDENTIALS = _WEBAUTHN_CREDENTIALS;
  TWebAuthNCredentials = WEBAUTHN_CREDENTIALS;
  PWEBAUTHN_CREDENTIALS = ^WEBAUTHN_CREDENTIALS;
  PWebAuthNCredentials = PWEBAUTHN_CREDENTIALS;

//+------------------------------------------------------------------------------------------
// Information about credential with extra information, such as, dwTransports
//-------------------------------------------------------------------------------------------

const WEBAUTHN_CTAP_TRANSPORT_USB = $00000001;
      WEBAUTHN_CTAP_TRANSPORT_NFC = $00000002;
      WEBAUTHN_CTAP_TRANSPORT_BLE = $00000004;
      WEBAUTHN_CTAP_TRANSPORT_TEST = $00000008;
      WEBAUTHN_CTAP_TRANSPORT_INTERNAL = $00000010;
      WEBAUTHN_CTAP_TRANSPORT_FLAGS_MASK = $0000001F;

      WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION = 1;

type
  _WEBAUTHN_CREDENTIAL_EX = packed record
    // Version of this structure, to allow for modifications in the future.
    dwVersion : DWORD;

    // Size of pbID.
    cbId : DWORD;
    // Unique ID for this particular credential.
//    _Field_size_bytes_(cbId)
    pbId : PBYTE;

    // Well-known credential type specifying what this particular credential is.
    pwszCredentialType : LPCWSTR;

    // Transports. 0 implies no transport restrictions.
    dwTransports : DWORD;
  end;
  WEBAUTHN_CREDENTIAL_EX = _WEBAUTHN_CREDENTIAL_EX;
  PWEBAUTHN_CREDENTIAL_EX = ^WEBAUTHN_CREDENTIAL_EX;
  PPWEBAUTHN_CREDENTIAL_EX = ^PWEBAUTHN_CREDENTIAL_EX;

//+------------------------------------------------------------------------------------------
// Information about credential list with extra information
//-------------------------------------------------------------------------------------------

type
  _WEBAUTHN_CREDENTIAL_LIST = packed record
    cCredentials : DWORD;
//    _Field_size_(cCredentials)
    ppCredentials : PPWEBAUTHN_CREDENTIAL_EX;
  end;
  WEBAUTHN_CREDENTIAL_LIST = _WEBAUTHN_CREDENTIAL_LIST;
  PWEBAUTHN_CREDENTIAL_LIST = ^WEBAUTHN_CREDENTIAL_LIST;

//+------------------------------------------------------------------------------------------
// Credential Information for WebAuthNGetPlatformCredentialList API
//-------------------------------------------------------------------------------------------

const WEBAUTHN_CREDENTIAL_DETAILS_VERSION_1 = 1;
      WEBAUTHN_CREDENTIAL_DETAILS_CURRENT_VERSION = WEBAUTHN_CREDENTIAL_DETAILS_VERSION_1;

type
  _WEBAUTHN_CREDENTIAL_DETAILS = packed record
    // Version of this structure, to allow for modifications in the future.
    dwVersion : DWORD;

    // Size of pbCredentialID.
    cbCredentialID : DWORD;
    // _Field_size_bytes_(cbCredentialID)
    pbCredentialID : PBYTE;

    // RP Info
    pRpInformation : PWebAuthnRPEntityInformation;

    // User Info
    pUserInformation : PWebAuthUserEntityInformation;

    // Removable or not.
    bRemovable : BOOL;
  end;
  WEBAUTHN_CREDENTIAL_DETAILS = _WEBAUTHN_CREDENTIAL_DETAILS;
  PWEBAUTHN_CREDENTIAL_DETAILS = ^WEBAUTHN_CREDENTIAL_DETAILS;
  TWebAuthCredentialDetails = _WEBAUTHN_CREDENTIAL_DETAILS;
  PWebAuthCredentialDetails = PWEBAUTHN_CREDENTIAL_DETAILS;
  PPWebAuthCredentialDetails = ^PWebAuthCredentialDetails;

type
  _WEBAUTHN_CREDENTIAL_DETAILS_LIST = packed record
    cCredentialDetails : DWORD ;
    // _Field_size_(cCredentialDetails)
    ppCredentialDetails : PPWebAuthCredentialDetails;
  end;
  WEBAUTHN_CREDENTIAL_DETAILS_LIST = _WEBAUTHN_CREDENTIAL_DETAILS_LIST;
  TWebAuthCredntialDetailsList = _WEBAUTHN_CREDENTIAL_DETAILS_LIST;
  PWebAuthCredntialDetailsList = ^TWebAuthCredntialDetailsList;
  PPWebAuthCredntialDetailsList = ^PWebAuthCredntialDetailsList;
  PCWebAuthCredntialDetailsList = PWebAuthCredntialDetailsList;

const WEBAUTHN_GET_CREDENTIALS_OPTIONS_VERSION_1 = 1;
      WEBAUTHN_GET_CREDENTIALS_OPTIONS_CURRENT_VERSION = WEBAUTHN_GET_CREDENTIALS_OPTIONS_VERSION_1;

type
 _WEBAUTHN_GET_CREDENTIALS_OPTIONS = packed record
    // Version of this structure, to allow for modifications in the future.
    dwVersion : DWORD;

    // Optional.
    pwszRpId : LPCWSTR;

    // Optional. BrowserInPrivate Mode. Defaulting to FALSE.
    bBrowserInPrivateMode : BOOL;
 end;
 WEBAUTHN_GET_CREDENTIALS_OPTIONS = _WEBAUTHN_GET_CREDENTIALS_OPTIONS;
 TWebAuthnGetCredentialsOptions = _WEBAUTHN_GET_CREDENTIALS_OPTIONS;
 PWebAuthnGetCredentialsOptions = ^TWebAuthnGetCredentialsOptions;
 PCWebAuthnGetCredentialsOptions = PWebAuthnGetCredentialsOptions;

//+------------------------------------------------------------------------------------------
// PRF values.
//-------------------------------------------------------------------------------------------

const WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH = 32;

// SALT values below by default are converted into RAW Hmac-Secret values as per PRF extension.
//   - SHA-256(UTF8Encode("WebAuthn PRF") || 0x00 || Value)
//
// Set WEBAUTHN_CTAP_HMAC_SECRET_VALUES_FLAG in dwFlags in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
//   if caller wants to provide RAW Hmac-Secret SALT values directly. In that case,
//   values if provided MUST be of WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH size.

type
  _WEBAUTHN_HMAC_SECRET_SALT = packed record
    // Size of pbFirst.
    cbFirst : DWORD;
    //_Field_size_bytes_(cbFirst)
    pbFirst : PBYTE;                                  // Required

    // Size of pbSecond.
    cbSecond : DWORD;
    //_Field_size_bytes_(cbSecond)
    pbSecond : PBYTE;
  end;
  WEBAUTHN_HMAC_SECRET_SALT = _WEBAUTHN_HMAC_SECRET_SALT;
  TWebAuthnHMACSecretSalt = _WEBAUTHN_HMAC_SECRET_SALT;
  PWebAuthnHMACSecretSalt = ^TWebAuthnHMACSecretSalt;
  PCWebAuthnHMACSecretSalt = PWebAuthnHMACSecretSalt;

type
  _WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT = packed record
    // Size of pbCredID.
    cbCredID : DWORD;
    //_Field_size_bytes_(cbCredID)
    pbCredID : PBYTE;                                 // Required

    // PRF Values for above credential
    pHmacSecretSalt : PWebAuthnHMACSecretSalt;     // Required
  end;
  WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT = _WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT;
  TWebAuthCredWithHMACSecretSalt = _WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT;
  PWebAuthCredWithHMACSecretSalt = ^TWebAuthCredWithHMACSecretSalt;
  PCWebAuthCredWithHMACSecretSalt = PWebAuthCredWithHMACSecretSalt;

type
   _WEBAUTHN_HMAC_SECRET_SALT_VALUES = packed record
    pGlobalHmacSalt : PWebAuthnHMACSecretSalt;

    cCredWithHmacSecretSaltList : DWORD;
    //_Field_size_(cCredWithHmacSecretSaltList)
    pCredWithHmacSecretSaltList : PWebAuthCredWithHMACSecretSalt;
  end;
  WEBAUTHN_HMAC_SECRET_SALT_VALUES = _WEBAUTHN_HMAC_SECRET_SALT_VALUES;
  TWebAuthHMACSecretSaltValues = WEBAUTHN_HMAC_SECRET_SALT_VALUES;
  PWebAuthHMACSecretSaltValues = ^TWebAuthHMACSecretSaltValues;
  PCWebAuthHMACSecretSaltValues = PWebAuthHMACSecretSaltValues;

//+------------------------------------------------------------------------------------------
// Hmac-Secret extension
//-------------------------------------------------------------------------------------------

const WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET = 'hmac-secret';
// Below type definitions is for WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET
// MakeCredential Input Type:   BOOL.
//      - pvExtension must point to a BOOL with the value TRUE.
//      - cbExtension must contain the sizeof(BOOL).
// MakeCredential Output Type:  BOOL.
//      - pvExtension will point to a BOOL with the value TRUE if credential
//        was successfully created with HMAC_SECRET.
//      - cbExtension will contain the sizeof(BOOL).
// GetAssertion Input Type:     Not Supported
// GetAssertion Output Type:    Not Supported

//+------------------------------------------------------------------------------------------
//  credProtect  extension
//-------------------------------------------------------------------------------------------

     WEBAUTHN_USER_VERIFICATION_ANY = 0;
     WEBAUTHN_USER_VERIFICATION_OPTIONAL = 1;
     WEBAUTHN_USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST = 2;
     WEBAUTHN_USER_VERIFICATION_REQUIRED = 3;

type
  _WEBAUTHN_CRED_PROTECT_EXTENSION_IN = packed record
    // One of the above WEBAUTHN_USER_VERIFICATION_* values
    dwCredProtect : DWORD;
    // Set the following to TRUE to require authenticator support for the credProtect extension
    bRequireCredProtect : BOOL;
  end;
  WEBAUTHN_CRED_PROTECT_EXTENSION_IN = _WEBAUTHN_CRED_PROTECT_EXTENSION_IN;
  PWEBAUTHN_CRED_PROTECT_EXTENSION_IN = ^WEBAUTHN_CRED_PROTECT_EXTENSION_IN;


const WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT = 'credProtect';
// Below type definitions is for WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT
// MakeCredential Input Type:   WEBAUTHN_CRED_PROTECT_EXTENSION_IN.
//      - pvExtension must point to a WEBAUTHN_CRED_PROTECT_EXTENSION_IN struct
//      - cbExtension will contain the sizeof(WEBAUTHN_CRED_PROTECT_EXTENSION_IN).
// MakeCredential Output Type:  DWORD.
//      - pvExtension will point to a DWORD with one of the above WEBAUTHN_USER_VERIFICATION_* values
//        if credential was successfully created with CRED_PROTECT.
//      - cbExtension will contain the sizeof(DWORD).
// GetAssertion Input Type:     Not Supported
// GetAssertion Output Type:    Not Supported

//+------------------------------------------------------------------------------------------
//  credBlob  extension
//-------------------------------------------------------------------------------------------

type
  _WEBAUTHN_CRED_BLOB_EXTENSION = packed record
    // Size of pbCredBlob.
    cbCredBlob : DWORD;
    // _Field_size_bytes_(cbCredBlob)
    pbCredBlob : PBYTE;
  end;
  WEBAUTHN_CRED_BLOB_EXTENSION = _WEBAUTHN_CRED_BLOB_EXTENSION;
  TWebAuthCredBlobExtension = _WEBAUTHN_CRED_BLOB_EXTENSION;
  PWebAuthCredBlobExtension = ^TWebAuthCredBlobExtension;
  PCWebAuthCredBlobExtension = PWebAuthCredBlobExtension;

const WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB = 'credBlob';
// Below type definitions is for WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB
// MakeCredential Input Type:   WEBAUTHN_CRED_BLOB_EXTENSION.
//      - pvExtension must point to a WEBAUTHN_CRED_BLOB_EXTENSION struct
//      - cbExtension must contain the sizeof(WEBAUTHN_CRED_BLOB_EXTENSION).
// MakeCredential Output Type:  BOOL.
//      - pvExtension will point to a BOOL with the value TRUE if credBlob was successfully created
//      - cbExtension will contain the sizeof(BOOL).
// GetAssertion Input Type:     BOOL.
//      - pvExtension must point to a BOOL with the value TRUE to request the credBlob.
//      - cbExtension must contain the sizeof(BOOL).
// GetAssertion Output Type:    WEBAUTHN_CRED_BLOB_EXTENSION.
//      - pvExtension will point to a WEBAUTHN_CRED_BLOB_EXTENSION struct if the authenticator
//        returns the credBlob in the signed extensions
//      - cbExtension will contain the sizeof(WEBAUTHN_CRED_BLOB_EXTENSION).

//+------------------------------------------------------------------------------------------
//  minPinLength  extension
//-------------------------------------------------------------------------------------------

const WEBAUTHN_EXTENSIONS_IDENTIFIER_MIN_PIN_LENGTH = 'minPinLength';
// Below type definitions is for WEBAUTHN_EXTENSIONS_IDENTIFIER_MIN_PIN_LENGTH
// MakeCredential Input Type:   BOOL.
//      - pvExtension must point to a BOOL with the value TRUE to request the minPinLength.
//      - cbExtension must contain the sizeof(BOOL).
// MakeCredential Output Type:  DWORD.
//      - pvExtension will point to a DWORD with the minimum pin length if returned by the authenticator
//      - cbExtension will contain the sizeof(DWORD).
// GetAssertion Input Type:     Not Supported
// GetAssertion Output Type:    Not Supported

//+------------------------------------------------------------------------------------------
// Information about Extensions.
//-------------------------------------------------------------------------------------------
type
  _WEBAUTHN_EXTENSION = packed record
    pwszExtensionIdentifier : LPCWSTR;
    cbExtension : DWORD;
    pvExtension : Pointer;
  end;
  WEBAUTHN_EXTENSION = _WEBAUTHN_EXTENSION;
  PWEBAUTHN_EXTENSION = ^WEBAUTHN_EXTENSION;

  _WEBAUTHN_EXTENSIONS = packed record
    cExtensions : DWORD;
//    _Field_size_(cExtensions)
   pExtensions : PWEBAUTHN_EXTENSION;
  end;
  WEBAUTHN_EXTENSIONS = _WEBAUTHN_EXTENSIONS;
  PWEBAUTHN_EXTENSIONS = ^WEBAUTHN_EXTENSIONS;

//+------------------------------------------------------------------------------------------
// Options.
//-------------------------------------------------------------------------------------------

const WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY = 0;
      WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM = 1;
      WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 2;
      WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2 = 3;

      WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY = 0;
      WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED = 1;
      WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED = 2;
      WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 3;

      WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY = 0;
      WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE = 1;
      WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT = 2;
      WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT = 3;

      WEBAUTHN_ENTERPRISE_ATTESTATION_NONE = 0;
      WEBAUTHN_ENTERPRISE_ATTESTATION_VENDOR_FACILITATED = 1;
      WEBAUTHN_ENTERPRISE_ATTESTATION_PLATFORM_MANAGED = 2;

      WEBAUTHN_LARGE_BLOB_SUPPORT_NONE = 0;
      WEBAUTHN_LARGE_BLOB_SUPPORT_REQUIRED = 1;
      WEBAUTHN_LARGE_BLOB_SUPPORT_PREFERRED = 2;


      WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1 = 1;
      WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_2 = 2;
      WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3 = 3;
      WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4 = 4;
      WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_5 = 5;
      WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_5;

type
  _WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = packed record
    // Version of this structure, to allow for modifications in the future.
    dwVersion : DWORD;

    // Time that the operation is expected to complete within.
    // This is used as guidance, and can be overridden by the platform.
    dwTimeoutMilliseconds : DWORD;

    // Credentials used for exclusion.
    CredentialList : WEBAUTHN_CREDENTIALS;

    // Optional extensions to parse when performing the operation.
    Extensions : WEBAUTHN_EXTENSIONS;

    // Optional. Platform vs Cross-Platform Authenticators.
    dwAuthenticatorAttachment : DWORD;

    // Optional. Require key to be resident or not. Defaulting to FALSE;
    bRequireResidentKey : BOOL;

    // User Verification Requirement.
    dwUserVerificationRequirement : DWORD;

    // Attestation Conveyance Preference.
    dwAttestationConveyancePreference : DWORD;

    // Reserved for future Use
    dwFlags : DWORD;

    //
    // The following fields have been added in WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_2
    //

    // Cancellation Id - Optional - See WebAuthNGetCancellationId
    pCancellationId : PGUID;

    //
    // The following fields have been added in WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3
    //

    // Exclude Credential List. If present, "CredentialList" will be ignored.
    pExcludeCredentialList : PWEBAUTHN_CREDENTIAL_LIST;

    //
    // The following fields have been added in WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4
    //

    // Enterprise Attestation
    dwEnterpriseAttestation : DWORD;

    // Large Blob Support: none, required or preferred
    //
    // NTE_INVALID_PARAMETER when large blob required or preferred and
    //   bRequireResidentKey isn't set to TRUE
    dwLargeBlobSupport : DWORD;

    // Optional. Prefer key to be resident. Defaulting to FALSE. When TRUE,
    // overrides the above bRequireResidentKey.
    bPreferResidentKey : BOOL;

    //
    // The following fields have been added in WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_5
    //

    // Optional. BrowserInPrivate Mode. Defaulting to FALSE.
    bBrowserInPrivateMode : BOOL;

  end;

  WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = _WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS;
  PWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = ^WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS;
  PCWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = PWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS;
  TWebAuthnAuthenticatorMakeCredentialOptions = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS;

const WEBAUTHN_CRED_LARGE_BLOB_OPERATION_NONE = 0;
      WEBAUTHN_CRED_LARGE_BLOB_OPERATION_GET = 1;
      WEBAUTHN_CRED_LARGE_BLOB_OPERATION_SET = 2;
      WEBAUTHN_CRED_LARGE_BLOB_OPERATION_DELETE = 3;


      WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1 = 1;
      WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_2 = 2;
      WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_3 = 3;
      WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4 = 4;
      WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_5 = 5;
      WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6 = 6;
      WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6;

(*
    Information about flags.
*)

      WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG = $00100000;


type
  _WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = packed record
    // Version of this structure, to allow for modifications in the future.
    dwVersion : DWORD;

    // Time that the operation is expected to complete within.
    // This is used as guidance, and can be overridden by the platform.
    dwTimeoutMilliseconds : DWORD;

    // Allowed Credentials List.
    CredentialList : WEBAUTHN_CREDENTIALS;

    // Optional extensions to parse when performing the operation.
    Extensions : WEBAUTHN_EXTENSIONS;

    // Optional. Platform vs Cross-Platform Authenticators.
    dwAuthenticatorAttachment : DWORD;

    // User Verification Requirement.
    dwUserVerificationRequirement : DWORD;

    // Reserved for future Use
    dwFlags : DWORD;

    //
    // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_2
    //

    // Optional identifier for the U2F AppId. Converted to UTF8 before being hashed. Not lower cased.
    pwszU2fAppId : PCWSTR;

    // If the following is non-NULL, then, set to TRUE if the above pwszU2fAppid was used instead of
    // PCWSTR pwszRpId;
    pbU2fAppId : PBOOL;

    //
    // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_3
    //

    // Cancellation Id - Optional - See WebAuthNGetCancellationId
    pCancellationId : PGUID;

    //
    // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4
    //

    // Allow Credential List. If present, "CredentialList" will be ignored.
    pAllowCredentialList : PWEBAUTHN_CREDENTIAL_LIST;

    //
    // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_5
    //

    dwCredLargeBlobOperation : DWORD;

    // Size of pbCredLargeBlob
    cbCredLargeBlob : DWORD;
    //_Field_size_bytes_(cbCredLargeBlob)
    pbCredLargeBlob : PBYTE;

    //
    // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6
    //

    // PRF values which will be converted into HMAC-SECRET values according to WebAuthn Spec.
    pHmacSecretSaltValues : PWebAuthHMACSecretSaltValues;

    // Optional. BrowserInPrivate Mode. Defaulting to FALSE.
    bBrowserInPrivateMode : BOOL;
  end;
  WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = _WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS;
  PWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = ^WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS;
  TWebAuthNAuthenticatorGetAsserrtionOptions = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS;
  PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = PWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS;


//+------------------------------------------------------------------------------------------
// Attestation Info.
//
//-------------------------------------------------------------------------------------------
const WEBAUTHN_ATTESTATION_DECODE_NONE = 0;
      WEBAUTHN_ATTESTATION_DECODE_COMMON = 1;
// WEBAUTHN_ATTESTATION_DECODE_COMMON supports format types
//  L"packed"
//  L"fido-u2f"

    WEBAUTHN_ATTESTATION_VER_TPM_2_0 = '2.0';

type
  _WEBAUTHN_X5C = packed record
    // Length of X.509 encoded certificate
    cbData : DWORD;
    // X.509 encoded certificate bytes
//    _Field_size_bytes_(cbData)
    pbData : PBYTE;
  end;
  WEBAUTHN_X5C = _WEBAUTHN_X5C;
  PWEBAUTHN_X5C = ^WEBAUTHN_X5C;

// Supports either Self or Full Basic Attestation

// Note, new fields will be added to the following data structure to
// support additional attestation format types, such as, TPM.
// When fields are added, the dwVersion will be incremented.
//
// Therefore, your code must make the following check:
//  "if (dwVersion >= WEBAUTHN_COMMON_ATTESTATION_CURRENT_VERSION)"

const WEBAUTHN_COMMON_ATTESTATION_CURRENT_VERSION = 1;

type 
  _WEBAUTHN_COMMON_ATTESTATION = packed record
    // Version of this structure, to allow for modifications in the future.
    dwVersion : DWORD;

    // Hash and Padding Algorithm
    //
    // The following won't be set for "fido-u2f" which assumes "ES256".
    pwszAlg : PCWSTR;
    lAlg : LongInt;      // COSE algorithm

    // Signature that was generated for this attestation.
    cbSignature : DWORD;
//    _Field_size_bytes_(cbSignature)
    pbSignature : PBYTE;

    // Following is set for Full Basic Attestation. If not, set then, this is Self Attestation.
    // Array of X.509 DER encoded certificates. The first certificate is the signer, leaf certificate.
    cX5c : DWORD;
//    _Field_size_(cX5c)
    pX5c : PWEBAUTHN_X5C;

    // Following are also set for tpm
    pwszVer : PCWSTR; // L"2.0"
    cbCertInfo : DWORD;
//    _Field_size_bytes_(cbCertInfo)
    pbCertInfo : PBYTE;
    cbPubArea : DWORD;
//    _Field_size_bytes_(cbPubArea)
    pbPubArea : PBYTE;
  end;
  WEBAUTHN_COMMON_ATTESTATION = _WEBAUTHN_COMMON_ATTESTATION;
  PWEBAUTHN_COMMON_ATTESTATION = ^WEBAUTHN_COMMON_ATTESTATION;

const WEBAUTHN_ATTESTATION_TYPE_PACKED = 'packed';
      WEBAUTHN_ATTESTATION_TYPE_U2F = 'fido-u2f';
      WEBAUTHN_ATTESTATION_TYPE_TPM = 'tpm';
      WEBAUTHN_ATTESTATION_TYPE_NONE = 'none';

      WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_1 = 1;
      WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_2 = 2;
      WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3 = 3;
      WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_4 = 4;
      WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION = WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_4;

type
  _WEBAUTHN_CREDENTIAL_ATTESTATION = packed record
    // Version of this structure, to allow for modifications in the future.
    dwVersion : DWORD;

    // Attestation format type
    pwszFormatType : PCWSTR;

    // Size of cbAuthenticatorData.
    cbAuthenticatorData : DWORD;
    // Authenticator data that was created for this credential.
//    _Field_size_bytes_(cbAuthenticatorData)
    pbAuthenticatorData : PBYTE;

    // Size of CBOR encoded attestation information
    //0 => encoded as CBOR null value.
    cbAttestation : DWORD;
    //Encoded CBOR attestation information
//    _Field_size_bytes_(cbAttestation)
    pbAttestation : PBYTE;

    dwAttestationDecodeType : DWORD;
    // Following depends on the dwAttestationDecodeType
    //  WEBAUTHN_ATTESTATION_DECODE_NONE
    //      NULL - not able to decode the CBOR attestation information
    //  WEBAUTHN_ATTESTATION_DECODE_COMMON
    //      PWEBAUTHN_COMMON_ATTESTATION;
    pvAttestationDecode : PVOID;

    // The CBOR encoded Attestation Object to be returned to the RP.
    cbAttestationObject : DWORD;
//    _Field_size_bytes_(cbAttestationObject)
    pbAttestationObject : PBYTE;

    // The CredentialId bytes extracted from the Authenticator Data.
    // Used by Edge to return to the RP.
    cbCredentialId : DWORD;
//    _Field_size_bytes_(cbCredentialId)
    pbCredentialId : PBYTE;

    //
    // Following fields have been added in WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_2
    //

    Extensions : WEBAUTHN_EXTENSIONS;

    //
    // Following fields have been added in WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3
    //

    // One of the WEBAUTHN_CTAP_TRANSPORT_* bits will be set corresponding to
    // the transport that was used.
    dwUsedTransport : DWORD;

    //
    // Following fields have been added in WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_4
    //

    bEpAtt : BOOL;
    bLargeBlobSupported : BOOL;
    bResidentKey : BOOL;

  end;
  WEBAUTHN_CREDENTIAL_ATTESTATION = _WEBAUTHN_CREDENTIAL_ATTESTATION;
  PWEBAUTHN_CREDENTIAL_ATTESTATION = ^WEBAUTHN_CREDENTIAL_ATTESTATION;
  PPWEBAUTHN_CREDENTIAL_ATTESTATION = ^PWEBAUTHN_CREDENTIAL_ATTESTATION;

//+------------------------------------------------------------------------------------------
// authenticatorGetAssertion output.
//-------------------------------------------------------------------------------------------

const WEBAUTHN_CRED_LARGE_BLOB_STATUS_NONE                  =  0;
      WEBAUTHN_CRED_LARGE_BLOB_STATUS_SUCCESS               =  1;
      WEBAUTHN_CRED_LARGE_BLOB_STATUS_NOT_SUPPORTED         =  2;
      WEBAUTHN_CRED_LARGE_BLOB_STATUS_INVALID_DATA          =  3;
      WEBAUTHN_CRED_LARGE_BLOB_STATUS_INVALID_PARAMETER     =  4;
      WEBAUTHN_CRED_LARGE_BLOB_STATUS_NOT_FOUND             =  5;
      WEBAUTHN_CRED_LARGE_BLOB_STATUS_MULTIPLE_CREDENTIALS  =  6;
      WEBAUTHN_CRED_LARGE_BLOB_STATUS_LACK_OF_SPACE         =  7;
      WEBAUTHN_CRED_LARGE_BLOB_STATUS_PLATFORM_ERROR        =  8;
      WEBAUTHN_CRED_LARGE_BLOB_STATUS_AUTHENTICATOR_ERROR   =  9;

      WEBAUTHN_ASSERTION_VERSION_1                          = 1;
      WEBAUTHN_ASSERTION_VERSION_2                          = 2;
      WEBAUTHN_ASSERTION_VERSION_3                          = 3;
      WEBAUTHN_ASSERTION_CURRENT_VERSION = WEBAUTHN_ASSERTION_VERSION_3;

type
  _WEBAUTHN_ASSERTION = packed record
    // Version of this structure, to allow for modifications in the future.
    dwVersion : DWORD;

    // Size of cbAuthenticatorData.
    cbAuthenticatorData : DWORD;
    // Authenticator data that was created for this assertion.
//    _Field_size_bytes_(cbAuthenticatorData)
    pbAuthenticatorData : PBYTE;

    // Size of pbSignature.
    cbSignature : DWORD;
    // Signature that was generated for this assertion.
//    _Field_size_bytes_(cbSignature)
    pbSignature : PBYTE;

    // Credential that was used for this assertion.
    Credential : WEBAUTHN_CREDENTIAL;

    // Size of User Id
    cbUserId : DWORD;
    // UserId
//    _Field_size_bytes_(cbUserId)
    pbUserId : PBYTE;

    //
    // Following fields have been added in WEBAUTHN_ASSERTION_VERSION_2
    //

    Extensions : WEBAUTHN_EXTENSIONS;

    // Size of pbCredLargeBlob
    cbCredLargeBlob : DWORD;
    //_Field_size_bytes_(cbCredLargeBlob)
    pbCredLargeBlob : PBYTE;

    dwCredLargeBlobStatus : DWORD;

    //
    // Following fields have been added in WEBAUTHN_ASSERTION_VERSION_3
    //
    pHmacSecret : PWebAuthnHMACSecretSalt;
  end;
  WEBAUTHN_ASSERTION = _WEBAUTHN_ASSERTION;
  TWebAutNAssertion = WEBAUTHN_ASSERTION;
  PWEBAUTHN_ASSERTION = ^WEBAUTHN_ASSERTION;
  PWebAutNAssertion = PWEBAUTHN_ASSERTION;

  PPWEBAUTHN_ASSERTION = ^PWEBAUTHN_ASSERTION;

//+------------------------------------------------------------------------------------------
// APIs.
//-------------------------------------------------------------------------------------------

function WebAuthNGetApiVersionNumber : DWORD; stdcall; external cWebAuthLibName;
function WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable( var pbIsUserVerifyingPlatformAuthenticatorAvailable : BOOL ) : HRESULT; stdcall; external cWebAuthLibName;
function WebAuthNAuthenticatorMakeCredential( hWnd : HWND;  // _In_
                                              pRpInformation : PWebAuthnRPEntityInformation; // _In_
                                              pUserInformation : PCWebAuthUserEntityInformation; // _In_
                                              pPubKeyCredParams : PCWEBAUTHN_COSE_CREDENTIAL_PARAMETERS; // _In_
                                              pWebAuthNClientData : PCWebAuthnClientData; // _In_
                                              pWebAuthNMakeCredentialOptions : PCWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS; // _In_opt_
                                              var pWebAuthNCredentialAttestation : PWEBAUTHN_CREDENTIAL_ATTESTATION // _Outptr_result_maybenull_
                                              ) : HRESULT; stdcall; external cWebAuthLibName;

function WebAuthNAuthenticatorGetAssertion( hWnd : HWND; // _IN_
                                            pwszRpId : LPCWSTR; // _In_
                                            pWebAuthNClientData : PCWebAuthnClientData; // _In_
                                            pWebAuthNGetAssertionOptions : PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS; // _In_opt_    
                                            var pWebAuthNAssertion : PWEBAUTHN_ASSERTION // _Outptr_result_maybenull_
                                            ) : HRESULT; stdcall; external cWebAuthLibName; 

procedure WebAuthNFreeCredentialAttestation(
                                             pWebAuthNCredentialAttestation : PWEBAUTHN_CREDENTIAL_ATTESTATION // _In_opt_ 
                                           ); stdcall; external cWebAuthLibName;

procedure WebAuthNFreeAssertion(
                                 pWebAuthNAssertion : PWEBAUTHN_ASSERTION // _In_ 
                               ); stdcall; external cWebAuthLibName;

function WebAuthNGetCancellationId( 
                                    var pCancellationId : TGUID // _Out_
                                  ) : HRESULT; stdcall; external cWebAuthLibName;

function WebAuthNCancelCurrentOperation(
    pCancellationId : PGUID ) : HRESULT; stdcall; external cWebAuthLibName;

// Returns NTE_NOT_FOUND when credentials are not found.
function WebAuthNGetPlatformCredentialList(
    pGetCredentialsOptions : PCWebAuthnGetCredentialsOptions;
    var ppCredentialDetailsList : PWebAuthCredntialDetailsList) : HRESULT; stdcall; external cWebAuthLibName;

procedure WebAuthNFreePlatformCredentialList(
    pCredentialDetailsList : PWebAuthCredntialDetailsList); stdcall; external cWebAuthLibName;

function WebAuthNDeletePlatformCredential(
    cbCredentialId : DWORD;
    //_In_reads_bytes_(cbCredentialId)const BYTE *pbCredentialId
    pbCredentialId : PBYTE )  : HRESULT; stdcall; external cWebAuthLibName;

//
// Returns the following Error Names:
//  L"Success"              - S_OK
//  L"InvalidStateError"    - NTE_EXISTS
//  L"ConstraintError"      - HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED),
//                            NTE_NOT_SUPPORTED,
//                            NTE_TOKEN_KEYSET_STORAGE_FULL
//  L"NotSupportedError"    - NTE_INVALID_PARAMETER
//  L"NotAllowedError"      - NTE_DEVICE_NOT_FOUND,
//                            NTE_NOT_FOUND,
//                            HRESULT_FROM_WIN32(ERROR_CANCELLED),
//                            NTE_USER_CANCELLED,
//                            HRESULT_FROM_WIN32(ERROR_TIMEOUT)
//  L"UnknownError"         - All other hr values
//
function WebAuthNGetErrorName(
                              hr : HRESULT // _In_
                              ) : PCWSTR; stdcall; external cWebAuthLibName; 

function WebAuthNGetW3CExceptionDOMError(
                                         hr : HRESULT // _IN_
                                         ) : HRESULT; stdcall; external cWebAuthLibName;

implementation

end.
