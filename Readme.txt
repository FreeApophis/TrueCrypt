
TrueCrypt 1.0a Source Code Distribution
Copyright (C) 2004 TrueCrypt Team, truecrypt.org

See 'Docs\License.txt' file for license covering this distribution.
See 'Release\Setup files\TrueCrypt User Guide.pdf' file for more information.


Requirements for building TrueCrypt:

- Microsoft Visual Studio .NET 2003
- Windows XP (build 2600 or higher) Driver Development Kit


Before building TrueCrypt:

- Open 'Driver\Makefile' and change the 'DDK' variable to point to your
  Windows XP DDK directory
- Open 'Service\Service.vcproj' and change all 'AdditionalIncludeDirectories'
  variables to include your Windows XP DDK installation directory


Building TrueCrypt:

- Open 'TrueCrypt.sln' solution in Microsoft Visual Studio
- Make sure 'All' is the active solution configuration
- Build the solution
- If successful, you should have a new TrueCrypt build in 'Release' directory.
