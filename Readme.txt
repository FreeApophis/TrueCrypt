
WARNING: Using TrueCrypt is not secure as it may contain unfixed security issues

The development of TrueCrypt was ended in 5/2014 after Microsoft terminated
support of Windows XP. Windows 8/7/Vista and later offer integrated support for
encrypted disks and virtual disk images. Such integrated support is also
available on other platforms. You should migrate any data encrypted by TrueCrypt
to encrypted disks or virtual disk images supported on your platform.



Important
=========

You may use the source code contained in this archive only if you accept and
agree to the license terms contained in the file 'License.txt', which is
included in this archive.

Note that the license specifies, for example, that a derived work must not be
called 'TrueCrypt'.



Contents
========

I. Windows
	Requirements for Building TrueCrypt for Windows
	Instructions for Building TrueCrypt for Windows

II. Linux and Mac OS X
	Requirements for Building TrueCrypt for Linux and Mac OS X
	Instructions for Building TrueCrypt for Linux and Mac OS X



I. Windows
==========

Requirements for Building TrueCrypt for Windows:
------------------------------------------------

- Microsoft Visual C++ 2008 SP1 (Professional Edition or compatible)
- Microsoft Visual C++ 1.52
- Microsoft Windows SDK for Windows 7 (configured for Visual C++)
- Microsoft Windows Driver Kit 7.1.0 (build 7600.16385.1)
- RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki) 2.20
  header files
- NASM assembler 2.08 or compatible
- gzip compressor


Instructions for Building TrueCrypt for Windows:
------------------------------------------------

1) Create an environment variable 'MSVC16_ROOT' pointing to the folder 'MSVC15'
   extracted from the Visual C++ 1.52 self-extracting package.

   Note: The 16-bit installer MSVC15\SETUP.EXE cannot be run on 64-bit Windows,
   but it is actually not necessary to run it. You only need to extract the
   folder 'MSVC15', which contains the 32-bit binaries required to build the
   TrueCrypt Boot Loader.

2) If you have installed the Windows Driver Development Kit in another
   directory than '%SYSTEMDRIVE%\WinDDK', create an environment variable
   'WINDDK_ROOT' pointing to the DDK installation directory.

3) Copy the PKCS #11 header files to a standard include path or create an
   environment variable 'PKCS11_INC' pointing to the directory where
   the PKCS #11 header files are installed.

4) Open the solution file 'TrueCrypt.sln' in Microsoft Visual Studio 2008.

5) Select 'All' as the active solution configuration.

6) Build the solution.

7) If successful, there should be newly built TrueCrypt binaries in the
   'Release' folder.



II. Linux and Mac OS X
======================

Requirements for Building TrueCrypt for Linux and Mac OS X:
-----------------------------------------------------------

- GNU Make
- GNU C++ Compiler 4.0 or compatible
- Apple Xcode (Mac OS X only)
- NASM assembler 2.08 or compatible (x86/x64 architecture only)
- pkg-config
- wxWidgets 2.8 shared library and header files installed or
  wxWidgets 2.8 library source code
- FUSE library and header files
- RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki) 2.20
  header files located in a standard include path or in a directory
  defined by the environment variable 'PKCS11_INC'


Instructions for Building TrueCrypt for Linux and Mac OS X:
-----------------------------------------------------------

1) Change the current directory to the root of the TrueCrypt source code.

2) If you have no wxWidgets shared library installed, run the following
   command to configure the wxWidgets static library for TrueCrypt and to
   build it: 

   $ make WX_ROOT=/usr/src/wxWidgets wxbuild

   The variable WX_ROOT must point to the location of the source code of the
   wxWidgets library. Output files will be placed in the './wxrelease/'
   directory.

3) To build TrueCrypt, run the following command:

   $ make

   or if you have no wxWidgets shared library installed:
   
   $ make WXSTATIC=1

4) If successful, the TrueCrypt executable should be located in the directory
   'Main'.

By default, a universal executable supporting both graphical and text user
interface is built. To build a console-only executable, which requires no GUI
library, use the 'NOGUI' parameter:

   $ make NOGUI=1 WX_ROOT=/usr/src/wxWidgets wxbuild
   $ make NOGUI=1 WXSTATIC=1
