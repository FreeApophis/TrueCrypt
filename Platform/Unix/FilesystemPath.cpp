/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Platform/FilesystemPath.h"
#include "Platform/SystemException.h"
#include "Platform/StringConverter.h"
#include <sys/stat.h>

namespace TrueCrypt
{
	void FilesystemPath::Delete () const
	{
		throw_sys_sub_if (remove (string (*this).c_str()) == -1, Path);
	}

	FilesystemPathType::Enum FilesystemPath::GetType () const
	{
		// Strip trailing directory separator
		wstring path = Path;
		size_t pos = path.find_last_not_of (L'/');
		if (path.size() > 2 && pos != path.size() - 1)
			path = path.substr (0, pos + 1);

		struct stat statData;
		throw_sys_sub_if (stat (StringConverter::ToSingle (path).c_str(), &statData) != 0, Path);
		
		if (S_ISREG (statData.st_mode)) return FilesystemPathType::File;
		if (S_ISDIR (statData.st_mode)) return FilesystemPathType::Directory;
		if (S_ISCHR (statData.st_mode)) return FilesystemPathType::CharacterDevice;
		if (S_ISBLK (statData.st_mode)) return FilesystemPathType::BlockDevice;
		if (S_ISLNK (statData.st_mode)) return FilesystemPathType::SymbolickLink;

		return FilesystemPathType::Unknown;
	}
}
