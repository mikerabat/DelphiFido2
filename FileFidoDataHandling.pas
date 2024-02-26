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

unit FileFidoDataHandling;

// this class handles the fido data per file based and in the current directory
// there is a file user.txt that maps usernames and userhandles (random bytes) to a credential id
// there is a file sigcounter.txt that maps credential ids to device counters
// there is a set of files that store the credential data - the filename is based on the credential id
//     and the extension describes the data: credid.pk, credid.x5c  -> public key
//                                           credid.sig -> credential signature used in the initiation process
// for each assertion there is a challenge file challengeID.chg
// the challenge sent to the client on the user initialization is stored as challengeid.json

interface

uses SysUtils, Classes, WebauthnHandler, AuthData, Fido2, SuperObject;

// ###########################################
// #### User handling based on simple files
type
  TFileFidoDatarHandling = class(TInterfacedObject, IFidoDataHandling)
  private
    fDataPath : string;
    fUserFile : string;
    fSigCounterFile : string;
    fGlobCS : THandle;

    function EnterGlobalMutex : boolean;
    procedure LeaveGlobalMutex;
  public
    procedure CleanupPendingChallenges(aChallenge : string = '');
    function IsAlreadRegistered( uname : string ) : boolean; overload;
    function IsAlreadRegistered( uname : string; var credIDFN : string ) : boolean; overload;

    function IsChallengeInitiated( challenge : string; var data : ISuperObject ) : boolean;
    function CredentialDataFromId(credId: string; var data : string): TFidoCredentialFmt;

    procedure SaveUserInitChallenge( user : TFidoUserStartRegister );
    function SaveCred( fmt : string; id : string; userHandle : string; challenge : string; cred : TFidoCredVerify; authData : TAuthData ) : boolean;

    function CredToUser(credId: string; var uname: string): boolean;
    procedure SaveAssertChallengeData( challenge : ISuperObject );
    function LoadAssertChallengeData( challenge : string ) : ISuperObject;
    function CheckSigCounter(credId: string; authData: TAuthData): boolean;

    //function IsAlreadRegistered( uname : string ) : boolean; overload;
//    function IsAlreadRegistered( uname : string; var credID : string ) : boolean; overload;
//
//    function IsChallengeInitiated( challenge : string ) : boolean;
//
//    procedure SaveUserInitChallenge( user : TFidoUserStartRegister );
//    procedure SaveCred( challenge : string; cred : TFidoCredVerify; authData : TAuthData );
//    function CredToUser(credId: string; var uname: string): boolean;
//
//    function CheckSigCounter(credId: string; authData: TAuthData): boolean;
//    procedure SaveAssertChallengeData( challenge : ISuperObject );
//    function LoadAssertChallengeData( challenge : string ) : ISuperObject;

    constructor Create;
    destructor Destroy; override;
  end;


implementation

uses cbor, Windows, Registry;

{ TFileFidoUserHandling }

function TFileFidoDatarHandling.IsAlreadRegistered(uname: string): boolean;
var credIDFN : string;
begin
     Result := IsAlreadRegistered(uname, credIDFN);
end;

procedure TFileFidoDatarHandling.CleanupPendingChallenges(aChallenge: string);
begin

end;

constructor TFileFidoDatarHandling.Create;
var semaphoreName : string;
begin
     // ###########################################
     // #### load the data directory from the registry - default is the current directory
     with TRegIniFile.Create( KEY_READ or KEY_WOW64_64KEY ) do
     try
        RootKey := HKEY_LOCAL_MACHINE;
        OpenKeyReadOnly('Software\FidoWebauthn');
        fDataPath := IncludeTrailingPathDelimiter( ReadString('', 'DataPath', '.') );
        semaphoreName := ReadString('', 'Semaphore', 'Global\FIDODataHandler');
     finally
            Free;
     end;

     // create a system wide mutex so the watchdogs from 2 httpd.exe processes do not
     // interfer with each other (e.g. produce a lock conflict in the db)
     // note: httpd.exe as a service always starts two instances
     fGlobCS := CreateMutex(nil, False, PChar( semaphoreName) );

     if (fGlobCS = 0) and (GetLastError = ERROR_ACCESS_DENIED) then
        fGlobCS := OpenMutex( MUTEX_ALL_ACCESS, False, PChar( semaphoreName ) );

     fUserFile := fDataPath + 'users.txt';
     fSigCounterFile := fDataPath + 'sigCounters.txt';

     assert( (fGlobCS <> 0), 'Cannot create a global semaphore');

     inherited Create;
end;

function TFileFidoDatarHandling.CredentialDataFromId(credId: string;
  var data: string): TFidoCredentialFmt;
var sr : TSearchRec;
    aFmt : string;
begin
     data := '';
     Result := fmNone;
     if FindFirst( credID + '.*.cred', faArchive, sr ) = 0 then
     begin
          with TStringList.Create do
          try
             LoadFromFile(sr.Name);
             data := Text;
          finally
                 Free;
          end;

          aFmt := Copy(sr.Name, 1, Length(sr.Name) - Length('.cred'));
          aFmt := ExtractFileExt(aFmt);

          if SameText(aFmt, 'packed')
          then
              Result := fmFido2
          else if SameText(aFmt, 'fido-u2f')
          then
              Result := fmU2F
          else if SameText(aFmt, 'tpm')
          then
              Result := fmTPM;
     end;
     SysUtils.FindClose(sr);
end;

function TFileFidoDatarHandling.CredToUser(credId: string;
  var uname: string): boolean;
var i : integer;
    UserCred : String;
begin
     Result := FileExists(fUserFile);

     if not Result then
        exit;

     if EnterGlobalMutex then
     try
        Result := False;
        with TStringList.Create do
        try
           LoadFromFile(fUserFile);

           for i := 0 to Count - 1 do
           begin
                userCred := ValueFromIndex[i];
                if credId = userCred then
                begin
                     uname := Names[i];
                     Result := True;
                     break;
                end;
           end;
        finally
               Free;
        end;
     finally
            LeaveGlobalMutex;
     end;
end;


destructor TFileFidoDatarHandling.Destroy;
begin
     if fGlobCS <> INVALID_HANDLE_VALUE then
        CloseHandle(fGlobCS);

     inherited;
end;

function TFileFidoDatarHandling.EnterGlobalMutex : boolean;
var retVal : LongWord;
begin
     retVal := WAIT_OBJECT_0;
     if fGlobCS <> 0 then
        repeat
              retVal := WaitForSingleObject(fGlobCS, 0);

        until retVal <> WAIT_TIMEOUT;

     Result := retVal = WAIT_OBJECT_0;
end;

function TFileFidoDatarHandling.IsAlreadRegistered(uname: string;
  var credIDFN: string): boolean;
var idx : integer;
begin
     Result := True;

     if EnterGlobalMutex then
     try
        with TStringList.Create do
        try
           if FileExists(fUserFile) then
           begin
                LoadFromFile(fUserFile );
           end;

           idx := IndexOfName( uname );
           Result := idx  >= 0;

           if Result then
              credIDFN := ValueFromIndex[idx];
        finally
               Free;
        end;
     finally
            LeaveGlobalMutex;
     end;
end;

function TFileFidoDatarHandling.IsChallengeInitiated(challenge: string; var data : ISuperObject): boolean;
var userDataFn : string;
begin
     userDataFn := Base64UrlFixup( challenge ) + '.json';

     // check if the challenge was requested here -> we can associate it with the user now ;)
     Result := FileExists( fDataPath + userDataFn );

     if Result then
     begin
          with TStringList.Create do
          try
             LoadFromFile(userDataFN);
             data := SO( Text );
          finally
                 Free;
          end;
     end;
end;

procedure TFileFidoDatarHandling.LeaveGlobalMutex;
begin
     if (fGlobCS <> 0) then
        ReleaseMutex(fGlobCS);
end;

function TFileFidoDatarHandling.LoadAssertChallengeData(
  challenge: string): ISuperObject;
var challengeFs : string;
begin
     Result := nil;
     challengeFs := fDataPath + challenge + '.chl';

     if not FileExists(challengeFs) then
        exit;

     if EnterGlobalMutex then
     try
        // ###########################################
        // #### check if credential id is in the list
        with TStringList.Create do
        try
           LoadFromFile(challengeFS);
           Result := SO(Text);
        finally
               Free;
        end;
     finally
            LeaveGlobalMutex;
     end;
end;

procedure TFileFidoDatarHandling.SaveAssertChallengeData(challenge: ISuperObject);
var fs : TFileStream;
begin
     if EnterGlobalMutex then
     try
        fs := TFileStream.Create(fDataPath + challenge.S['publicKey.challenge'] + '.chl', fmCreate);
        try
           challenge.SaveTo(fs);
        finally
               fs.Free;
        end;
     finally
            LeaveGlobalMutex;
     end;
end;

function TFileFidoDatarHandling.SaveCred(fmt : string; id : string; userHandle : string;
  challenge : string; cred : TFidoCredVerify; authData : TAuthData) : boolean;
var userFn : string;
    sCred : UTF8String;
    clientData : ISuperObject;
    credData : ISuperObject;
begin
     Result := False;
     if EnterGlobalMutex then
     try
        userFn := fDataPath + Base64UrlFixup( challenge ) + '.json';

        // load username
        with TStringList.Create do
        try
           LoadFromFile( userFn, TEncoding.ASCII );
           clientData := SO( Text );
        finally
               Free;
        end;

        if SameText(fmt, 'none') then
        begin
             // none has only the public key stored in authData ->
             sCred := UTF8String( Base64URLEncode(authData.RawData) );

             with TFileStream.Create( id + '.' + fmt + '.cred', fmCreate ) do
             try
                WriteBuffer( sCred[1], Length(sCred)*Sizeof(AnsiChar));
             finally
                    Free;
             end;
        end
        else
        begin
             credData := SO;
             credData.S['cert.pk'] := id + '.pk';
             credData.S['cert.sig'] := id + '.sig';
             credData.S['cert.x5c'] := id + '.x5c';

             cred.SavePKToFile(fDataPath + id + '.pk');
             cred.SaveSigToFile(fDataPath + id + '.sig');
             cred.SaveX5cToFile(fDataPath + id + '.x5c');

             credData.O['user'] := clientData.O['publicKey.user'].Clone;
             credDAta.SaveTo(id + '.' + fmt + '.cred');
        end;

        // link the credential to the username...
        with TStringList.Create do
        try
           if FileExists(fUserFile) then
              LoadFromFile( fUserFile );
           Add(clientData.S['publicKey.user.name'] + '=' + id);

           // -> add the user handle to the file
           if clientData.S['publicKey.user.id'] <> '' then
              Add(clientData.S['publicKey.user.id'] + '=' + id);

           SaveToFile( fUserFile );
        finally
               Free;
        end;

        // ###########################################
        // #### Write device data to check the signal counter
        with TStringList.Create do
        try
           if FileExists(fSigCounterFile) then
              LoadFromFile( fSigCounterFile );

           Add( id + '=' + IntToStr(authData.SigCount));
           SaveToFile( fSigCounterFile );
        finally
               Free;
        end;
     finally
            LeaveGlobalMutex;
     end;
end;

procedure TFileFidoDatarHandling.SaveUserInitChallenge(
  user: TFidoUserStartRegister);
var challengeFN : string;
    obj : ISuperObject;
    s : Utf8String;
begin
     obj := user.ToJson;

     s := UTF8String( obj.AsJSon );
     challengeFN := Base64URLEncode( @user.Challenge[0], sizeof(user.Challenge));
     challengeFN := fDataPath + challengeFN + '.json';
     if EnterGlobalMutex then
     try
        with TFileStream.Create( challengeFN, fmCreate) do
        try
           WriteBuffer( s[1], length(s));
        finally
               Free;
        end;
     finally
            LeaveGlobalMutex;
     end;
end;

function TFileFidoDatarHandling.CheckSigCounter(credId : string; authData: TAuthData): boolean;
var idx : integer;
    sigCnt: LongWord;
begin
     Result := False;
     if not FileExists(fSigCounterFile) then
        exit;

     if EnterGlobalMutex then
     try
        with TStringList.Create do
        try
           LoadFromFile( fSigCounterFile );

           idx := IndexOfName(credId);

           if idx < 0 then
              exit;

           sigCnt := StrToInt( ValueFromIndex[ idx ] );
           Result := ((sigCnt = 0) and (authData.SigCount = 0)) or
                     (sigCnt < authData.SigCount);

           if Result and (authData.SigCount > 0) then
           begin
                ValueFromIndex[idx] := IntToStr(authData.SigCount);

                SaveToFile(fSigCounterFile);
           end;
        finally
               Free;
        end;
     finally
            LeaveGlobalMutex;
     end;
end;

initialization
  SetDefFidoDataHandler(TFileFidoDatarHandling.Create);

end.
