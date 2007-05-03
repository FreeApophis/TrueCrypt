This archive contains TrueCrypt 4.3a setup and documentation.


If you have never used TrueCrypt before, we recommend that you read the 
chapter "Beginner's Tutorial" in the TrueCrypt User Guide, which can be 
found in the 'Setup Files' folder. 



IMPORTANT NOTES -- PLEASE READ
==============================

If you are upgrading from an older version of TrueCrypt, it is normally not 
necessary to uninstall it first. However, if any errors occur during the 
process of installation, please uninstall TrueCrypt, restart the operating 
system, and then try to install the new version of TrueCrypt again. Note that 
when you uninstall TrueCrypt, no TrueCrypt volume is removed or modified. 
To uninstall TrueCrypt on Windows XP, click Start Menu -> Settings -> Control 
Panel -> Add or Remove Programs -> TrueCrypt -> Change/Remove. To uninstall 
TrueCrypt on Windows Vista, click Start Menu -> Control Panel -> 
Programs - Uninstall a program -> TrueCrypt -> Change/Remove.


IMPORTANT NOTE TO USERS WHO USE VOLUMES CREATED BY TRUECRYPT 4.0 OR EARLIER: 
To prevent an attack reported in November 2005, which affects plausible 
deniability, we strongly recommend that you move data from your TrueCrypt 
volume to a new volume created by this version. Description of the attack: 
If a series of certain plaintext blocks is written to a mounted volume 
(i.e., if it is correctly encrypted), it is, with a very high probability, 
possible to distinguish the volume from random data. This affects volumes 
created by all versions of TrueCrypt prior to 4.1, except volumes encrypted 
with AES-Blowfish or AES-Blowfish-Serpent. 
Even if you do not need plausible deniability, we highly recommend you to 
move your data from your TrueCrypt volume (which is encrypted in CBC mode) 
to a new volume created by this version (which will be encrypted in LRW 
mode). LRW mode is more secure than CBC mode.


IMPORTANT NOTE TO USERS UPGRADING FROM TRUECRYPT 3.0 OR 3.0A: 
Note that after you upgrade to this new version of TrueCrypt, due to a bug 
in v3.0 and 3.0a, it will not be possible to mount hidden volumes created by 
TrueCrypt 3.0 or 3.0a located on some removable media, e.g., some USB memory 
sticks (does not apply to file-hosted containers). If that is the case, 
please before upgrading to this new version, move your files to a temporary 
TrueCrypt volume on a non-removable medium or to a non-hidden volume on a 
removable medium, and move the data from the old hidden volume to this 
temporary one. Then install this new version of TrueCrypt, create a new 
hidden volume, and move your files from the temporary volume to it. Please 
see the 'Version History' in the documentation for more information. 


IMPORTANT NOTE TO USERS UPGRADING FROM TRUECRYPT 2.1 OR EARLIER: 
TrueCrypt volumes encrypted using the IDEA encryption algorithm cannot be 
mounted using this version. If you have such a volume, before upgrading, 
please create a new TrueCrypt volume using a cipher other than IDEA and move 
your files to this new volume.


Before using TrueCrypt, we recommend that you read the TrueCrypt User Guide, 
which can be found in the 'Setup Files' folder. To view or print it, you 
need Adobe Reader, which is freely available at http://www.adobe.com. Note 
that the program documentation is also automatically copied to the folder to 
which TrueCrypt is installed, and will be accessible via the TrueCrypt user
interface (press F1 or select Help -> User's Guide).



REQUIREMENTS
============

- Any of the following operating systems:
  Windows Vista, Windows XP, Windows 2000, Windows Server 2003

- Free disk space: approximately 2 MB (this does not apply if you run
  TrueCrypt in 'traveller' mode).



INSTALLATION
============

To install TrueCrypt, run the file 'TrueCrypt Setup.exe'. It is not 
necessary to restart the operating system after the installation finishes.

It is also possible to run 'TrueCrypt.exe' directly from the 'Setup Files' 
folder without installation ('traveller' mode). However, if an older version 
of TrueCrypt is currently installed on the system, it must be uninstalled 
first.



WHAT IS NEW IN THIS VERSION OF TRUECRYPT
========================================

For a comprehensive list of changes, please refer to the TrueCrypt User 
Guide or visit http://www.truecrypt.org/history.php



FREQUENTLY ASKED QUESTIONS
==========================

http://www.truecrypt.org/faq.php



LICENSING INFORMATION
=====================

By installing and/or running and/or using and/or distributing and/or
modifying any part of this product you accept in full the responsibilities  
and obligations contained in the license whose text may be found in the file
'License.txt' in the 'Setup Files' folder.



FURTHER INFORMATION
===================

For further information, please visit http://www.truecrypt.org/

