This archive contains TrueCrypt 2.0 setup and documentation.

Copyright (c) 2004 TrueCrypt Foundation
(not associated with TrueCrypt Team, the authors of TrueCrypt 1.0)



WHAT IS NEW IN TRUECRYPT 2.0

Bug fixes:

- Data corruption will no longer occur when a TrueCrypt partition is
  subjected to heavy parallel usage (usually when copying files to or
  from a TrueCrypt partition). This also fixes the problem with 
  temporarily inaccessible files stored in TrueCrypt partitions.

  Note: File-hosted volumes were not affected by this bug.

- After dismounting and remounting a volume, its file system will be
  correctly recognized by the operating system and it will be 
  possible to reuse the same drive letter (Windows 2000 issue).

- The main program window will not be displayed when run in quiet 
  mode (command line usage). 

- Two password entry attempts are no longer necessary to be able to 
  mount a volume (command line usage).	

- All partitions will be visible to TrueCrypt even if one of them is 
  inaccessible to the operating system (an inaccessible partition 
  made all successive partitions on the hard disk unavailable to 
  TrueCrypt). 

- Relative path can be specified when mounting a file-hosted volume 
  (command line usage).

- Incorrect passwords are reported when auto-mounting (command line
  usage).

New features:

- AES-256 (Rijndael) encryption algorithm.

- The command line option /dismountall was renamed to /dismount which
  can now be also used to dismount a single volume by specifying its
  drive letter.

Improvements:

- Memory pages containing sensitive data are now locked to prevent 
  them from being swapped to the Windows page file.

- The state of the random pool will never be exported directly so the
  pool contents will not be leaked.

Miscellaneous:

- Released under GNU General Public License (GPL)



FUTURE

- 'Hidden' container
- Linux version
- Anti-Key-Logger Facilities
- HMAC-RIPEMD-160
- Keyfiles

and more.



INSTALLATION

Before installing TrueCrypt, you may want to read the TrueCrypt 
User's Guide. It is located in the folder called "Setup Files". To 
view or print it, you will need Adobe Acrobat Reader (freely 
available at www.adobe.com). Note that the program documentation 
will also be automatically installed into the program folder, and 
will later be accessible via the Start menu and the program user 
interface.

To install TrueCrypt, run "TrueCrypt Setup.exe".


REQUIREMENTS

- Free disk space: approximately 1.5 MB

- One of the following operating systems:
  Windows XP, Windows 2000, Windows 2003

- Administrator privileges


DISCLAIMER

Before installing this product (TrueCrypt), you must agree to the 
following terms and conditions: 

- YOU UNDERSTAND THAT THIS PRODUCT UTILIZES STRONG CRYPTOGRAPHY, AND
  THAT SHOULD THIS TECHNOLOGY BE REGULATED OR ILLEGAL IN YOUR
  COUNTRY, THE AUTHORS OF THE PRODUCT WILL NOT BE RESPONSIBLE FOR
  ANY CONSEQUENCES THAT YOUR IMPORTING AND/OR USING IT IN SUCH A
  COUNTRY MIGHT HAVE. 
- YOU UNDERSTAND THAT THE AUTHORS OF THE PRODUCT CANNOT BE HELD
  RESPONSIBLE FOR LOSS OF YOUR DATA OR ANY OTHER DAMAGE, DIRECT OR
  INDIRECT, CAUSED BY USING OR INSTALLING THE PRODUCT. 
- YOU UNDERSTAND THAT THIS PRODUCT CONTAINS NO "BACKDOOR", THAT
  WOULD ALLOW PARTIAL OR COMPLETE RECOVERY OF YOUR DATA WITHOUT
  KNOWING THE CORRECT PASSWORD. 
- YOU UNDERSTAND THAT THE AUTHORS OF THE PROGRAM CANNOT HELP YOU TO
  RECOVER YOUR DATA SHOULD YOU FORGET YOUR PASSWORD.

  You must also agree to the license displayed in the TrueCrypt
  Setup window.
 