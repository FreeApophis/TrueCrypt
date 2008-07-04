/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Platform_User
#define TC_HEADER_Platform_User

#include "PlatformBase.h"

#ifdef TC_UNIX
#include <unistd.h>
#include <sys/types.h>
#endif

namespace TrueCrypt
{
	struct UserId
	{
#ifdef TC_UNIX
		uid_t SystemId;
#endif
	};
}

#endif // TC_HEADER_Platform_User
