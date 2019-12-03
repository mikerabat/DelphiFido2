# DelphiFido2
Yubicos fido2.dll port for Delphi including some classes

This project is a base port of Yubicos fido dll. The example shows
a base functionality check of the port. Please note the project
is still work in progress and far from complete. E.g. my personal
test key is firmware 5.1 and as far as I know it does not implement 
credential management.

To get the project running you need to download the Fido.dll from

https://developers.yubico.com/libfido2/Releases/

The current implementation is based on V1.2.0.

Note the webauthn.pas is currently not used but already converted.

The project is based on Delphi 2010 and not tested on later versions - due to 
the use of some generics it is also not compatible with older versions.
