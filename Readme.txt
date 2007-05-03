This archive contains the complete source code of TrueCrypt 4.3a for all
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

III. Third-Party Developers (Contributors)

IV. Further Information



I. Windows
==========

Requirements for Building TrueCrypt for Windows:
------------------------------------------------

- Microsoft Visual Studio 2005 SP1
- Windows 2003 SP1 Driver Development Kit (build 3790.1830)
- Microsoft Windows SDK 6.0 (integrated with Visual Studio)

IMPORTANT:

The 64-bit editions of Windows Vista and in some cases (e.g. playback of HD DVD
content) also the 32-bit editions of Windows Vista do not allow the TrueCrypt
driver to run without an appropriate digital signature. Therefore, all .sys
files in official TrueCrypt binary packages are digitally signed with the
digital certificate of the TrueCrypt Foundation, which was issued by a
certification authority. At the end of each official .exe and .sys file,
there are embedded digital signatures and all related certificates (i.e. all
certificates in the relevant certification chain, such as the certification
authority certificates, CA-MS cross-certificate, and the TrueCrypt Foundation
certificate). Keep this in mind if you compile TrueCrypt and compare your
binaries with the official binaries. If your binaries are unsigned, the sizes
of the official binaries will usually be approximately 10 KB greater than sizes
of your binaries (if you use a different version of compiler or if you install
a different or no service pack for Visual Studio, there may be further
differences).


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

- Source code of the Linux kernel, version 2.6.5 or compatible. The version of
  the kernel source code and its configuration must match the one under which
  you will be running TrueCrypt. Linux kernel sources are available at:
  http://kernel.org/pub/linux/kernel/

  Note that Linux kernel headers, located in the 'include' directory, are
  not sufficient for compilation of the TrueCrypt kernel module. Fields of
  'dm_dev' structure must be accessed by TrueCrypt but they are defined only in
  an internal kernel header 'drivers/md/dm.h'. No appropriate accessor function
  is available. The complete source code of the Linux kernel is required for
  compilation of the kernel module.

  Also note that the Linux kernel lacks a stable external programming interface
  and, therefore, new kernel releases may break compatibility with external
  kernel modules. The TrueCrypt kernel module may fail to build, depending on
  the changes made to the Linux kernel by the kernel developers.


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



III. Third-Party Developers (Contributors)
==========================================

If you intend to implement a feature, please contact us first to make sure:

1) That the feature has not been implemented (we may have already implemented
   it, but haven't released the code yet).
2) That the feature is acceptable.
3) Whether we need help of third-party developers with implementing the feature.

Information on how to contact us can be found at:
http://www.truecrypt.org/contact.php



IV. Further Information
=======================

http://www.truecrypt.org
