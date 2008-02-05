/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Core_MountOptions
#define TC_HEADER_Core_MountOptions

#include "Platform/Serializable.h"
#include "Volume/Keyfile.h"
#include "Volume/Volume.h"
#include "Volume/VolumeSlot.h"
#include "Volume/VolumePassword.h"

namespace TrueCrypt
{
	struct MountOptions : public Serializable
	{
		MountOptions ()
			:
			CachePassword (false),
			NoFilesystem (false),
			PreserveTimestamps (true),
			Protection (VolumeProtection::None),
			Removable (false),
			SharedAccessAllowed (false),
			SlotNumber (0)
		{
		}

		MountOptions (const MountOptions &other) { CopyFrom (other); }
		virtual ~MountOptions () { }

		MountOptions &operator= (const MountOptions &other) { CopyFrom (other); return *this; }

		TC_SERIALIZABLE (MountOptions);

		bool CachePassword;
		wstring FilesystemOptions;
		wstring FilesystemType;
		shared_ptr <KeyfileList> Keyfiles;
		shared_ptr <DirectoryPath> MountPoint;
		bool NoFilesystem;
		shared_ptr <VolumePassword> Password;
		shared_ptr <VolumePath> Path;
		bool PreserveTimestamps;
		VolumeProtection::Enum Protection;
		shared_ptr <VolumePassword> ProtectionPassword;
		shared_ptr <KeyfileList> ProtectionKeyfiles;
		bool Removable;
		bool SharedAccessAllowed;
		VolumeSlotNumber SlotNumber;

	protected:
		void CopyFrom (const MountOptions &other);
	};
}

#endif // TC_HEADER_Core_MountOptions
