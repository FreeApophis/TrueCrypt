This archive contains the complete source code of TrueCrypt 4.3 for all
supported operating systems and all supported hardware platforms.


Important
=========

You may use the source code contained in this archive only if you agree to the
license contained in the file 'License.txt', which is included in this archive.
Note that the license specifies conditions under which you may modify TrueCrypt
(for example, that a derived work must not be called "TrueCrypt").



Contents
========

I. Windows
	Requirements for Building TrueCrypt for Windows
	Instructions for Building TrueCrypt for Windows

II. Linux
	Requirements for Building TrueCrypt for Linux
	Instructions for Building TrueCrypt for Linux
	Installing TrueCrypt
	Requirements for Running Truecrypt on Linux

III. Third-Party Developers

IV. Documentation



I. Windows
==========

Requirements for Building TrueCrypt for Windows:
------------------------------------------------

- Microsoft Visual Studio 2005
- Microsoft Windows SDK 6.0 or later
- Windows 2003 SP1 Driver Development Kit (build 3790.1830) or compatible

Note: All .sys and .exe files in official TrueCrypt binary packages are
digitally signed with the digital certificate of the TrueCrypt Foundation,
which was issued by a certification authority. The 64-bit editions of Windows
Vista and in some cases (e.g. playback of HD DVD content) also the 32-bit
editions of Windows Vista do not allow the TrueCrypt driver to run without
an appropriate digital signature. A digital signature and all related digital
certificates are embeded in (located at the end of) the file they pertain to.


Instructions for Building TrueCrypt for Windows:
------------------------------------------------

1) Set the 'WINDDK_3790_1830' environment variable to point to the Windows DDK
   root directory. Alternatively, edit the 'DDK' variable in the file
   'Driver\Makefile'.
2) Open the 'TrueCrypt.sln' solution in Microsoft Visual Studio.
3) Make sure 'All' is the active solution configuration.
4) Build the solution.
5) If successful, there should be newly built TrueCrypt binaries in the 
   'Release' folder.



II. Linux
=========

Requirements for Building TrueCrypt for Linux:
----------------------------------------------

- Standard development tools: make, gcc, ld, strip

- Source code of the Linux kernel, version 2.6.5 or compatible. Note that the
  Linux kernel lacks a stable external programming interface and, therefore,
  new kernel releases often break compatibility with external kernel modules.
  The TrueCrypt kernel module may fail to build, depending on changes made to
  the Linux kernel by the kernel developers. 

  The version of the kernel source code and its configuration must match the
  one under which you will be running TrueCrypt. Linux kernel sources are
  available at: http://kernel.org/pub/linux/kernel/


Instructions for Building TrueCrypt for Linux:
----------------------------------------------

To build TrueCrypt execute the following commands:

cd Linux
./build.sh

The build script will first verify requirements for building TrueCrypt.
You may be prompted for additional information, which cannot be determined
automatically. Then the building process will start.


Installing TrueCrypt:
---------------------

To build and install TrueCrypt, execute the following commands:

cd Linux
./install.sh

The installation script will first verify requirements for running TrueCrypt.
If successful, you will be prompted for installation options and the
installation will proceed.


Requirements for Running Truecrypt on Linux
-------------------------------------------

- Linux kernel version 2.6.5 or compatible
  
- Device mapper (dmsetup, http://sources.redhat.com/dm) and loop device
  (losetup) infrastructure, which are available in all major Linux
  distributions



III. Third-Party Developers
===========================

If you intend to implement a feature, please contact us first to make sure:

1) That the feature has not been implemented (we may have already implemented
   it, but haven't released the code yet).
2) That the feature is acceptable.
3) Whether we need help of third-party developers with implementing the feature.
 
Information on how to contact us can be found at: 
http://www.truecrypt.org/contact.php



IV. Documentation
==================

http://www.truecrypt.org/docs/
