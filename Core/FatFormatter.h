/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.7 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Core_FatFormatter
#define TC_HEADER_Core_FatFormatter

#include "Platform/Platform.h"

namespace TrueCrypt
{
	class FatFormatter
	{
	public:
		struct WriteSectorCallback
		{
			virtual ~WriteSectorCallback () { }
			virtual bool operator() (const BufferPtr &sector) = 0;
		};

		static void Format (WriteSectorCallback &writeSector, uint64 deviceSize, uint32 clusterSize);
	};
}

#endif // TC_HEADER_Core_FatFormatter
