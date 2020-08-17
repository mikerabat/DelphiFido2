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
  PWEBAUTHN_CREDENTIAL = ^WEBAUTHN_CREDENTIAL;

type
  _WEBAUTHN_CREDENTIALS = packed record
    cCredentials : DWORD;
//    _Field_size_(cCredentials)
    pCredentials : PWEBAUTHN_CREDENTIAL;
  end;
  WEBAUTHN_CREDENTIALS = _WEBAUTHN_CREDENTIALS;
  PWEBAUTHN_CREDENTIALS = ^WEBAUTHN_CREDENTIALS;

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

      WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1 = 1;
      WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_2 = 2;
      WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3 = 3;
      WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3;

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
  end;

  WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = _WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS;
  PWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = ^WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS;
  PCWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = PWEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS;
  TWebAuthnAuthenticatorMakeCredentialOptions = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS;

const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1 = 1;
      WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_2 = 2;
      WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_3 = 3;
      WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4 = 4;
      WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4;

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
  end;
  WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = _WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS;
  PWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS = ^WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS;
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
      WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION = WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3;

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
  end;
  WEBAUTHN_CREDENTIAL_ATTESTATION = _WEBAUTHN_CREDENTIAL_ATTESTATION;
  PWEBAUTHN_CREDENTIAL_ATTESTATION = ^WEBAUTHN_CREDENTIAL_ATTESTATION;
  PPWEBAUTHN_CREDENTIAL_ATTESTATION = ^PWEBAUTHN_CREDENTIAL_ATTESTATION;

//+------------------------------------------------------------------------------------------
// authenticatorGetAssertion output.
//-------------------------------------------------------------------------------------------

const WEBAUTHN_ASSERTION_CURRENT_VERSION = 1;

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
  end;
  WEBAUTHN_ASSERTION = _WEBAUTHN_ASSERTION;
  PWEBAUTHN_ASSERTION = ^WEBAUTHN_ASSERTION;
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
