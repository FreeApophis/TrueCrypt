/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Platform_Functor
#define TC_HEADER_Platform_Functor

#include "PlatformBase.h"

namespace TrueCrypt
{
	struct Functor
	{
		virtual ~Functor () { }
		virtual void operator() () = 0;
	};

	struct GetStringFunctor
	{
		virtual ~GetStringFunctor () { }
		virtual string operator() () = 0;
	};
}

#endif // TC_HEADER_Platform_Functor
