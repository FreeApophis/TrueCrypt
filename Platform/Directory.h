/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.6 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Platform_Directory
#define TC_HEADER_Platform_Directory

#include "PlatformBase.h"
#include "FilesystemPath.h"

namespace TrueCrypt
{
	class Directory
	{
	public:
		static void Create (const DirectoryPath &path);
		static DirectoryPath AppendSeparator (const DirectoryPath &path);
		static FilePathList GetFilePaths (const DirectoryPath &path = L".");

	private:
		Directory ();
	};
}

#endif // TC_HEADER_Platform_Directory
