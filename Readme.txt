
TrueCrypt 4.0 Source Code Distribution
Released by TrueCrypt Foundation


This archive contains the complete source code of TrueCrypt for all supported
operating systems and all supported hardware platforms.


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

V. Further Information



I. Windows
==========

Requirements for Building TrueCrypt for Windows:
------------------------------------------------

- Microsoft Visual Studio .NET 2003 (version 7.1) or compatible
- Windows 2003 SP1 Driver Development Kit (build 3790.1830) or compatible


Instructions for Building TrueCrypt for Windows:
------------------------------------------------

1) Open 'Driver\Makefile' and change the 'DDK' variable to point to your
   Windows DDK directory
2) Open the 'TrueCrypt.sln' solution in Microsoft Visual Studio
3) Make sure 'All' is the active solution configuration
4) Build the solution
5) If successful, you should have a new TrueCrypt build in the 'Release' folder.



II. Linux
=========

Requirements for Building TrueCrypt for Linux:
----------------------------------------------

- Standard development tools: make, gcc, ld, strip

- Source code of Linux kernel, version 2.6.5 or higher/compatible.
  The version of the kernel source code and its configuration must match the
  one under which you will be running TrueCrypt. Linux kernel sources are
  available at: http://kernel.org/pub/linux/kernel/

- Linux kernel source code must be configured and all modules built
  (make config modules)  


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
If successful, you will be prompted for installation options. Afterwards, the
following files will be installed:

Kernel/truecrypt.ko
Cli/truecrypt
Cli/Man/truecrypt.1


Requirements for Running Truecrypt on Linux
-------------------------------------------

- Linux kernel version 2.6.5 or any higher/compatible version
  
- Device mapper (dmsetup, http://sources.redhat.com/dm) and loop device
  (losetup) infrastructure, which are available in all major Linux
  distributions.



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

http://www.truecrypt.org/documentation.php



V. Further Information
=======================

http://www.truecrypt.org

