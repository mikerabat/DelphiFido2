# DelphiFido2
Yubicos fido2.dll port for Delphi including some classes

This project is a base port of Yubicos fido dll. The example shows
a base functionality check of the port. Please note the project
is still work in progress and far from complete. E.g. my personal
test key is firmware 5.1 and as far as I know it does not implement 
credential management.

To get the project running you need to download the Fido.dll from

https://developers.yubico.com/libfido2/Releases/

The current implementation is based on V1.11.0. But please note that the
biometrics api as well as blob support is not properly tested due to a lack of a such key here.

There is also a base implementation to check the functionality of the webauthn 
dll interface. The test project does not create a resident key. It points to 
fidotest.com which with a bit of change in the hosts file points to localhost.

The project is based on Delphi 2010 and also tested with Delphi 10.4.2 - due to 
the use of some generics it is not compatible with older versions.

There are external dependency on SuperObject used to decode and encode JSON.
Download and install it from https://github.com/hgourvest/superobject
and a Delphi CBOR implementation from https://github.com/mikerabat/DelphiCBOR.

## Apache module ##

There is now a small project available that allows to integrate the base functionality
of WebAuthn into an Apache 2.2 server. With Delphi 10.4 it is also possible to
create an Apache 2.4 module. For the newer Delphi versions the default Apache version is 2.4 - to change
this back to Apache 2.2 rename _Web.HTTPD24Impl_ in _fidoWebauthn.dpr_ project file to
_Web.HTTPD22Impl_. 

The project also relies on Indy and OpenSSL functionality for
the SHA-256 hashing so make sure you keep the latest Indy OpenSSL compatible binaries around.

Please note there is only a very simple file based key storage and no device storage implemented so anyone using that
should do it differently ;)

Please note that the WebAuthn website source is based on the great work of the webauthn.io guys!!

Installation:
* Setup an apache server (e.g. xamp or from https://www.apachelounge.com/download/)
* Add a folder webauthnmod to the apache installation and copy the cbor.dll, crypto-45.dll and fido2.dll to this folder.
* Point the Delphi Apache output folder to this folder
* Add the line 
   LoadModule fido2_module webuthmod/mod_fidoWebauthn.so
  to the httpd.conf file.
* Add the section: 
   <Location /auth2>
	SetHandler mod_fidoWebauthn-handler
   </Location>
   to the httpd.conf file. Note that the standard scripts provided here use this path (e.g. webauthn.js)
* Create a local https certificate (can be self signed) and enable encryption in the httpd.conf file.
  e.g. follow instructions on https://www.sslshopper.com/article-how-to-create-and-install-an-apache-self-signed-certificate.html
* Copy the provided htdocs files to setup a website over the original one.  
* To debug the module you can setup "Start->Parameter" Host Application in Delphi. Provide the httpd.exe there and add the option "-X" 
* One can change the default file data handling output directory by the registry value
     HKEY_LOCAL_MACHINE\Software\FidoWebauthn
           -> StringValue: DataPath
  If that value does not exist the current module directory is used.
* There is a global Semaphore to protect the access to the files. Per default value is 'Global\FIDODataHandler' but can changed
  by the registry value:
      HKEY_LOCAL_MACHINE\Software\FidoWebauthn
	  -> string: Semaphore to define the complete path used.

# WebAuthn

Microsoft implements it's own _WebAuthn_ functionality by the 'webauthn.dll'. There is also a project included here that
shows how to use that functionality in Delphi - check out _WebAuthDLLTest_ project for that purpose.