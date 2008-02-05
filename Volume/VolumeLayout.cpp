/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Volume/EncryptionMode.h"
#include "Volume/EncryptionModeCBC.h"
#include "Volume/EncryptionModeLRW.h"
#include "Volume/EncryptionModeXTS.h"
#include "VolumeLayout.h"

namespace TrueCrypt
{
	VolumeLayout::VolumeLayout ()
	{
	}

	VolumeLayout::~VolumeLayout ()
	{
	}

	VolumeLayoutList VolumeLayout::GetAvailableLayouts (VolumeType::Enum type)
	{
		VolumeLayoutList layouts;

		layouts.push_back (shared_ptr <VolumeLayout> (new VolumeLayoutV1Normal ()));
		layouts.push_back (shared_ptr <VolumeLayout> (new VolumeLayoutV1Hidden ()));

		if (type != VolumeType::Unknown)
		{
			VolumeLayoutList l;

			foreach (shared_ptr <VolumeLayout> vl, layouts)
			{
				if (vl->GetType() == type)
					l.push_back (vl);
			}

			layouts = l;
		}

		return layouts;
	}

	shared_ptr <VolumeHeader> VolumeLayout::GetHeader ()
	{
		if (Header.get() == nullptr)
			Header.reset (new VolumeHeader (GetHeaderSize()));

		return Header;
	}

	VolumeLayoutV1Normal::VolumeLayoutV1Normal ()
	{
		Type = VolumeType::Normal;
		HeaderOffset = 0;
		HeaderSize = 512;

		SupportedEncryptionAlgorithms = EncryptionAlgorithm::GetAvailableAlgorithms();

		SupportedEncryptionModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeXTS ()));
		SupportedEncryptionModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		SupportedEncryptionModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	uint64 VolumeLayoutV1Normal::GetDataOffset (uint64 volumeHostSize) const
	{
		return HeaderSize;
	}

	uint64 VolumeLayoutV1Normal::GetDataSize (uint64 volumeHostSize) const
	{
		return volumeHostSize - GetHeaderSize();
	}

	VolumeLayoutV1Hidden::VolumeLayoutV1Hidden ()
	{
		Type = VolumeType::Hidden;
		HeaderOffset = -512 * 3;
		HeaderSize = 512;

		SupportedEncryptionAlgorithms = EncryptionAlgorithm::GetAvailableAlgorithms();

		SupportedEncryptionModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeXTS ()));
		SupportedEncryptionModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeLRW ()));
		SupportedEncryptionModes.push_back (shared_ptr <EncryptionMode> (new EncryptionModeCBC ()));
	}

	uint64 VolumeLayoutV1Hidden::GetDataOffset (uint64 volumeHostSize) const
	{
		return volumeHostSize - GetDataSize (volumeHostSize) + HeaderOffset;
	}

	uint64 VolumeLayoutV1Hidden::GetDataSize (uint64 volumeHostSize) const
	{
		return Header->GetHiddenVolumeDataSize ();
	}
}
