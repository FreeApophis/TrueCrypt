
TrueCrypt 2.1a Source Code Distribution
Released by TrueCrypt Foundation, 2004-10-01

See 'Docs\License.txt' file for license covering this distribution.
See 'Release\Setup files\TrueCrypt User Guide.pdf' file for more information.


Requirements for building TrueCrypt:

- Microsoft Visual Studio .NET 2003
- Windows XP Driver Development Kit (build 2600 or higher)


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
