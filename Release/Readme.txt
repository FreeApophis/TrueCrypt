This archive contains TrueCrypt 3.1a setup and documentation.


IMPORTANT NOTES
===============

If you are upgrading from an older version of TrueCrypt, it is normally 
not necessary to uninstall it first. However, if any errors are
reported, we recommend that you uninstall the older version first (click
Start Menu -> Settings -> Control Panel -> Add or Remove Programs ->
-> TrueCrypt -> Change/Remove) and restart the operating system.
Note that uninstalling TrueCrypt never removes any TrueCrypt volumes. 


IMPORTANT NOTE TO USERS UPGRADING FROM TRUECRYPT 2.1 OR EARLIER:
TrueCrypt volumes encrypted using the IDEA encryption algorithm cannot
be mounted using this version. If you have such a volume, before
upgrading, please create a new TrueCrypt volume using a cipher other
than IDEA and move your files to this new volume.

IMPORTANT NOTE TO USERS UPGRADING FROM TRUECRYPT 3.0 OR 3.0A: Note that 
after you upgrade to this new version of TrueCrypt, due to a bug in v3.0 
and 3.0a, it will not be possible to mount hidden volumes created with 
TrueCrypt 3.0 or 3.0a located on some removable media, e.g., some USB 
memory sticks (does not apply to file-hosted containers). If that is the 
case, please before upgrading to this new version, move your files to a 
temporary TrueCrypt volume on a non-removable medium or to a non-hidden 
volume on a removable medium, and move the data from the old hidden 
volume to this temporary one. Then install this new version of 
TrueCrypt, create a new hidden volume, and move your files from the 
temporary volume to it. Please see the 'Version History' in the 
documentation for more information. If needed, TrueCrypt 3.0a is 
available at: http://truecrypt.sourceforge.net/downloads.php


Before using TrueCrypt, we recommend that you read the TrueCrypt User's
Guide, which can be found in the 'Setup Files' folder. To view or print
it, you will need Adobe Acrobat Reader (which is freely available at
http://www.adobe.com). Note that the program documentation is also
automatically copied to the folder to which TrueCrypt is installed, and 
will be accessible via the Start menu and the TrueCrypt user interface.



REQUIREMENTS
============

- One of the following operating systems:
  Windows XP, Windows 2000, Windows Server 2003

- Free disk space: approximately 1.4 MB (does not apply if you run
  TrueCrypt in 'traveller' mode).



INSTALLATION
============

To install TrueCrypt, run the file 'TrueCrypt Setup.exe'. It is not
necessary to restart the operating system after the installation
finishes.
Remark: It is also possible to run 'TrueCrypt.exe' directly from the
'Setup Files' folder without installation ('traveller' mode).



LICENSING INFORMATION
=====================

Before installing and/or running TrueCrypt (i.e., running 
'TrueCrypt.exe', 'TrueCrypt Setup.exe', or 'TrueCrypt Format.exe'), you
must agree to the license contained in the 'License.txt' file in the
'Setup Files' folder.



WHAT IS NEW IN TRUECRYPT 3.1A
=============================

Bug fixes:
	
- Volumes mounted as removable media can now be checked/repaired 
  ('chkdsk.exe'), defragmented, formatted, etc.

- The Volume Creation Wizard now respects default mount options set via 
  'Tools' -> 'Preferences'.

- Fixed bug which caused mount/dismount to fail on some systems.

- The TrueCrypt uninstaller is now always installed during installation.

- Relative paths can be used with the /volume option (command line 
  usage).

- Drive A: will no longer disappear from Windows Explorer (e.g., the 'My 
  Computer' list) after 'Dismount All'.

- Other minor bug fixes
  

Improvements:

- When running in 'traveller' mode, the TrueCrypt driver will be 
  unloaded when no longer needed (e.g., when the main application and/or 
  the last instance of the Volume Creation Wizard is closed and no 
  TrueCrypt volumes are mounted).

- Access mode (read-only or read-write) is now displayed in the volume 
  properties dialog.

- Other minor improvements

