
TrueCrypt 3.1a Source Code Distribution
Released by TrueCrypt Foundation, 2005-02-07

For license covering this distribution, please see 'Release\Setup Files\License.txt'.
For more information, please see 'Release\Setup Files\TrueCrypt User Guide.pdf' 


Requirements for building TrueCrypt:

- Microsoft Visual Studio .NET 2003 (7.1 or compatible)
- Windows XP Driver Development Kit (build 2600 or higher)


Before building TrueCrypt:

- Open 'Driver\Makefile' and change the 'DDK' variable to point to your
  Windows XP DDK directory


Building TrueCrypt:

- Open 'TrueCrypt.sln' solution in Microsoft Visual Studio
- Make sure 'All' is the active solution configuration
- Build the solution
- If successful, you should have a new TrueCrypt build in 'Release' directory.
