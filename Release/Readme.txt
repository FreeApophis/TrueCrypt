This archive contains TrueCrypt 3.0a setup and documentation.


IMPORTANT: TrueCrypt volumes encrypted using the IDEA encryption
algorithm cannot be mounted using this version. If you have such a
volume, before upgrading, please create a new TrueCrypt volume using
a cipher other than IDEA and move your files to this new volume.


Before installing TrueCrypt, we recommend that you read the TrueCrypt
User's Guide. It is located in the 'Setup Files' folder. To view or
print it, you will need Adobe Acrobat Reader (freely available at 
www.adobe.com). Note that the program documentation is also 
automatically copied to the folder to which TrueCrypt is installed,
and will be accessible via the Start menu and the TrueCrypt user
interface.


REQUIREMENTS

- Free disk space: approximately 1.4 MB

- One of the following operating systems:
  Windows XP, Windows 2000, Windows 2003


INSTALLATION

To install TrueCrypt, run the file 'TrueCrypt Setup.exe'. It is not
necessary to restart the operating system after the installation
finishes.

If you are upgrading from an older version of TrueCrypt, it should not
be necessary to uninstall it first. However, if the installer reports
any errors, we recommend uninstalling the older version first
(Start Menu -> Settings -> Control Panel -> Add or Remove Programs).
Note that uninstalling TrueCrypt never removes any TrueCrypt volumes.
You will be able to mount your TrueCrypt volumes again after you
reinstall TrueCrypt. 


LICENSING INFORMATION

Before installing this product (TrueCrypt), you must agree to the 
license displayed in the TrueCrypt Setup window (the text of the 
license is also contained in the file 'License.txt').


WHAT IS NEW IN TRUECRYPT 3.0A

Bug fixes:

- Data corruption will not occur when data is written to a volume
  encrypted with Twofish or Serpent while another TrueCrypt volume
  is mounted (applies also to volumes encrypted using a cascade of
  ciphers, out of which one is Twofish or Serpent).

- Other minor bug fixes


WHAT IS NEW IN TRUECRYPT 3.0

New Features:

- Ability to create and mount a hidden TrueCrypt volume (file container 
  or partition/device). This allows solving situations where the user is 
  forced by an adversary to reveal the password and cannot refuse to do 
  so (for example, when the adversary uses violence).
  
  The principle is that a TrueCrypt volume is created within another 
  TrueCrypt volume (within the free space on the volume). Even when the 
  outer volume is mounted, it is impossible to tell whether there is a 
  hidden volume within it or not, because free space on any TrueCrypt 
  volume is always filled with random data when the volume is created 
  and no part of the hidden volume can be distinguished from random 
  data.
  
  The password for the hidden volume must be different from the password 
  for the outer volume. To the outer volume, (before creating the hidden 
  volume within it) you should copy some sensitive-looking files that 
  you do NOT really want to hide. These files will be there for anyone 
  who would force you to hand over the password. You will reveal only 
  the password for the outer volume, not for the hidden one. Files that 
  are really sensitive will be stored on the hidden volume. 
  
  As it is very difficult or even impossible for an inexperienced user 
  to set the size of the hidden volume such that the hidden volume does 
  not overwrite any data on the outer volume, the Volume Creation Wizard 
  automatically scans the cluster bitmap of the outer volume (before the 
  hidden volume is created within it) and determines the maximum 
  possible size of the hidden volume.

  More information on the hidden volume feature may be found at:
  http://truecrypt.sourceforge.net/hiddenvolume.php

- Serpent encryption algorithm (256-bit key)

- Twofish encryption algorithm (256-bit key)

- Forced/"brutal" dismount (allows dismounting a volume containing files 
  being used by the system or an application).

- Cascades of ciphers added (e.g., AES-Twofish-Serpent, AES-Blowfish, 
  etc.) Each of the ciphers in a cascade uses its own encryption key 
  (the keys are mutually independent).

- Ability to mount a TrueCrypt volume that is being used by the system 
  or an application (shared access mode). 

- Ability to encrypt devices/partitions that are being used by the 
  system or an application (shared access mode).

- The 'Select Device' dialog and the 'Auto-Mount Partitions' facility 
  now support devices that do not contain any partitions.

- Encryption Algorithm Benchmark facility added to the Tools menu and to 
  the Volume Creation Wizard.

- A warning is displayed if Caps Lock is on when creating a new volume 
  or changing a password.

- When /l is omitted and /a is used, the first free drive letter is used 
  (command line usage)

- New command line option: /force or /f enables forced ("brutal") 
  dismount or mounting in shared mode (i.e., without exclusive access).

- Drive letters are now displayed in the 'Select Device' window
 

Bug fixes:

- 'Blue screen' errors (system crashes) will not occur when dismounting 
  a volume (remark: this bug was inherited from E4M).
  
- The 'Select Device' dialog will display also partitions being used by 
  the system or an application.

- Users without administrator privileges can now create file containers 
  under Windows Server 2003.
  
- If the size of a partition/device was not a multiple of 1024 bytes, 
  its last sector (512 bytes) was not used for TrueCrypt volume (the 
  volume was 512 bytes shorter than the partition/device). Remark: This 
  bug was inherited from E4M, so it applies also to encrypted 
  partitions/devices created by E4M.
  
- FAT volumes that are exactly 129 MB in size will not have zero size of 
  free space (129-MB FAT volumes created by the previous versions had no 
  free space available). 
  
- Other minor bug fixes


Improvements:

- The timestamp of a container (date and time that the container was 
  last accessed, and last modified) will not be updated when TrueCrypt 
  accesses the container (i.e., after dismounting, attempting to mount, 
  changing or attempting to change the password, or creating a hidden 
  volume within it). 
  
- The TrueCrypt Service is no longer necessary and has been removed 
  because its functions are now handled by the TrueCrypt driver.
  
- When 'Never save history' is checked, Windows is prevented from saving 
  the file names of the last accessed file containers to the 'Recent 
  Documents' and File Selector history. 
  
- Other minor improvements


Miscellaneous:

- TrueCrypt has been successfully tested on the Windows "Longhorn" 
  operating system (beta version of the future successor to Windows XP).
