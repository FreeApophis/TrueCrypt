/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Main_FavoriteVolume
#define TC_HEADER_Main_FavoriteVolume

#include "System.h"
#include "Main.h"

namespace TrueCrypt
{
	struct FavoriteVolume;
	typedef list < shared_ptr <FavoriteVolume> > FavoriteVolumeList;

	struct FavoriteVolume
	{
	public:
		FavoriteVolume () { }
		FavoriteVolume (const VolumePath &path, const DirectoryPath &mountPoint, VolumeSlotNumber slotNumber)
			: MountPoint (mountPoint), Path (path), SlotNumber (slotNumber) { }

		static FavoriteVolumeList LoadList ();
		static void SaveList (const FavoriteVolumeList &favorites);
		void ToMountOptions (MountOptions &options) const;

		DirectoryPath MountPoint;
		VolumePath Path;
		VolumeSlotNumber SlotNumber;
		
	protected:
		static wxString GetFileName () { return L"Favorite Volumes.xml"; }
	};
}

#endif // TC_HEADER_Main_FavoriteVolume
