/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.6 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Platform.h"
#include "Bios.h"

#pragma pack(1)

struct BiosMemoryMapEntry
{
	uint64 BaseAddress;
	uint64 Length;
	uint32 Type;
};

#pragma pack()

bool GetFirstBiosMemoryMapEntry (BiosMemoryMapEntry &entry);
bool GetNextBiosMemoryMapEntry (BiosMemoryMapEntry &entry);
