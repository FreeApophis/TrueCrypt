This archive contains TrueCrypt 3.1 setup and documentation.


IMPORTANT NOTES

If you are upgrading from an older version of TrueCrypt, it is normally
not necessary to uninstall it first (this does not apply to Windows
 2000 users). However, if the installer reports any errors, we recommend 
that you uninstall the older version (Start Menu -> Settings -> 
-> Control Panel -> Add or Remove Programs -> TrueCrypt ->
-> Change/Remove) and restart the operating system before installing
the new version.
Note that uninstalling TrueCrypt never removes any TrueCrypt volumes.
You will be able to mount your TrueCrypt volumes again after you
reinstall TrueCrypt. 

WARNING: TrueCrypt volumes encrypted using the IDEA encryption
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
  Windows XP, Windows 2000, Windows Server 2003


INSTALLATION

To install TrueCrypt, run the file 'TrueCrypt Setup.exe'. It is not
necessary to restart the operating system after the installation
finishes.
Remark: It is also possible to run 'TrueCrypt.exe' directly from the
'Setup Files' folder without installation ('traveller' mode).


LICENSING INFORMATION

Before installing this product (TrueCrypt), you must agree to the 
license displayed in the TrueCrypt Setup window (the text of the 
license is also contained in the file 'License.txt').


WHAT IS NEW IN TRUECRYPT 3.1

Improvements:

- Partitions/devices that are already in use by another driver (usually 
  an anti-virus utility) can now be mounted.
  
- It is now possible to run multiple instances of the TrueCrypt Volume 
  Creation Wizard.
  

New Features:

- TrueCrypt can now run in 'traveller' mode, which means that it does 
  not have to be installed on the operating system under which it is 
  run. There are two ways to run TrueCrypt in 'traveller' mode:
 
  1) After you unpack the binary distribution archive, you can directly 
  run 'TrueCrypt.exe'. 

  2) You can use the new 'Traveller Disk Setup' facility (accessible 
  from the 'Tools' menu) to prepare a special 'traveller' disk and 
  launch TrueCrypt from it. This facility can also configure a
  'traveller' disk in a way that when it is inserted, TrueCrypt is
  automatically started or a specified volume is mounted (note that this
  works only when the 'traveller' disk is a removable medium such as a
  CD or DVD; Windows XP SP2 is required in case of USB memory sticks). 
  
- Volumes can now be mounted as read-only. This can be set in the newly 
  implemented 'Mount Options' dialog, which can be opened from the 
  password entry dialog or by holding Control while clicking 'Mount'. 
  (Command line usage: '/mountoption ro')

- Volumes can now be mounted as removable media (for example to prevent 
  Windows from creating the 'Recycled' and/or 'System Volume 
  Information' folders on the volume). This can be set in the newly 
  implemented 'Mount Options' dialog, which can be opened from the 
  password entry dialog or by holding Control while clicking 'Mount'. 
  (Command line usage: '/mountoption rm')
  
- Default mount options can be configured in the main program 
  preferences (Tools -> Preferences).
  
- 'Refresh Drive Letters' function added to the tools menu. It can be 
  used when Windows Explorer fails to register a newly mounted volume 
  (for example when it is not shown in the 'My Computer' list).
  
- Volume can now be selected by dragging its icon to the TrueCrypt 
  program window (this also allows to avoid the Windows file selector).

- '/auto devices' auto-mounts all device/partition-hosted TrueCrypt 
  volumes (command line usage)
  

Bug fixes:

- The 'Auto-Mount Devices' facility will not mount 'phantom' partitions 
  on some removable media (e.g. USB memory sticks). 
  
- In some cases TrueCrypt did not use all available space on some 
  removable media (such as USB memory sticks). 
  Remark: This bug was inherited from E4M, so it applies also to volumes 
  created by E4M.

- Freezing caused by applications not responding to drive change 
  messages when mounting/dismounting TrueCrypt volumes will no longer 
  occur.
  
- Users are now prevented from setting a too small cluster size when 
  creating a FAT volume (which caused various problems).
  
- The command line parser no longer causes TrueCrypt to crash.
  
- Other minor bug fixes