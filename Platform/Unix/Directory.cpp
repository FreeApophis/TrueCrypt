/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <sys/stat.h>
#include "System.h"
#include "Platform/Directory.h"
#include "Platform/SystemException.h"

namespace TrueCrypt
{
	void Directory::Create (const DirectoryPath &path)
	{
		string p = path;
		throw_sys_sub_if (mkdir (p.c_str(), S_IRUSR | S_IWUSR | S_IXUSR) == -1, p);
	}

	DirectoryPath Directory::AppendSeparator (const DirectoryPath &path)
	{
		wstring p (path);

		if (p.find_last_of (L'/') + 1 != p.size())
			return p + L'/';

		return p;
	}

	FilePathList Directory::GetFilePaths (const DirectoryPath &path)
	{
		throw NotImplemented (SRC_POS);
	}
}
