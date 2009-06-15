/*
 Copyright (c) 2008-2009 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.7 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Platform/SystemException.h"
#include "Platform/SystemInfo.h"
#include <sys/utsname.h>

namespace TrueCrypt
{
	wstring SystemInfo::GetPlatformName ()
	{
#ifdef TC_LINUX
		return L"Linux";
#elif defined (TC_MACOSX)
		return L"Mac OS X";
#elif defined (TC_FREEBSD)
		return L"FreeBSD";
#elif defined (TC_SOLARIS)
		return L"Solaris";
#else
#	error GetPlatformName() undefined
#endif

	}

	vector <int> SystemInfo::GetVersion ()
	{
		struct utsname unameData;
		throw_sys_if (uname (&unameData) == -1);

		vector <string> versionStrings = StringConverter::Split (unameData.release, ".");
		vector <int> version;

		for (int i = 0; i < versionStrings.size(); ++i)
		{
			string s = versionStrings[i];

			size_t p = s.find_first_not_of ("0123456789");
			if (p != string::npos)
				s = s.substr (0, p);

			if (s.empty())
				break;

			version.push_back (StringConverter::ToUInt32 (s));
		}

		return version;
	}
}
