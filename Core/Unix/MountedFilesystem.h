/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Core_Unix_MountedFilesystem
#define TC_HEADER_Core_Unix_MountedFilesystem

#include "Platform/Platform.h"

namespace TrueCrypt
{
	struct MountedFilesystem
	{
	public:
		DevicePath Device;
		DirectoryPath MountPoint;
	};

	typedef list < shared_ptr <MountedFilesystem> > MountedFilesystemList;
}

#endif // TC_HEADER_Core_Unix_MountedFilesystem
