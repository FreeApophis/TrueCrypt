This archive contains TrueCrypt 2.1 setup and documentation.


WHAT IS NEW IN TRUECRYPT 2.1

New features:

- RIPEMD-160 hash algorithm added.  The user can now select which hash
  algorithm TrueCrypt will use (SHA-1 or RIPEMD-160). 

  Note: RIPEMD-160, which was designed by an open academic community,
  represents a valuable alternative to SHA-1 designed by the NSA and NIST.
  In the previous versions there was a risk that the whole program would
  be practically useless, should a major weakness be found in SHA-1. The 
  user-selected hash algorithm is used by the random number generator when
  creating new volumes, and by the header key derivation function (HMAC 
  based on a hash function, as specified in PKCS #5 v2.0). The random 
  number generator generates the master encryption key, salt, and the 
  values used to create IV and 'whitening' values.

- When changing a volume password, the user can now select the HMAC hash
  algorithm that will be used in deriving the new volume header key. 

- It is now possible to create NTFS TrueCrypt volumes and unformatted 
  TrueCrypt volumes. This enhancement also removes the 2,048 GB volume
  size limit. (Only FAT volumes can be created using the previous versions
  of TrueCrypt. Any FAT volume, encrypted or not, cannot be over 2,048 GB.)

- Header key content is now displayed in the Volume Creation Wizard window
  (instead of salt).

- Random pool, master key, and header key contents can be prevented from 
  being displayed in the Volume Creation Wizard window.

Bug fixes:

- When there is a mounted TrueCrypt container that is stored in another 
  TrueCrypt container, it will be possible to dismount both of them using 
  the 'Dismount All' function, and 'blue screen' errors will not occur
  upon system shutdown.

- Minor bug fixes to command line handling.

Improvements:

- Several minor improvements to the driver.

Miscellaneous:

- Released under the original E4M license to avoid potential problems
  relating to the GPL license (added the IDEA patent information and
  specific legal notices).


FUTURE

- 'Hidden' container
- Linux version
- Anti-Key-Logger Facilities
- Keyfiles

and more.


INSTALLATION

Before installing TrueCrypt, you may want to read the TrueCrypt 
User's Guide. It is located in the folder called 'Setup Files'. To 
view or print it, you will need Adobe Acrobat Reader (freely 
available at www.adobe.com). Note that the program documentation 
will also be automatically installed into the program folder, and 
will later be accessible via the Start menu and the program user 
interface.

To install TrueCrypt, run the file 'TrueCrypt Setup.exe'.


REQUIREMENTS

- Free disk space: approximately 1.5 MB

- One of the following operating systems:
  Windows XP, Windows 2000, Windows 2003

- Administrator privileges


LICENSING INFORMATION

Before installing this product (TrueCrypt), you must agree to the
license displayed in the TrueCrypt Setup window (the text of the
license is also contained in the file 'License.txt').
