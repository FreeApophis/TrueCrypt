/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Volume_VolumeLayout
#define TC_HEADER_Volume_VolumeLayout

#include "Platform/Platform.h"
#include "Volume/EncryptionAlgorithm.h"
#include "Volume/EncryptionMode.h"
#include "VolumeHeader.h"

namespace TrueCrypt
{
	class VolumeLayout;
	typedef list < shared_ptr <VolumeLayout> > VolumeLayoutList;

	class VolumeLayout
	{
	public:
		virtual ~VolumeLayout ();

		static VolumeLayoutList GetAvailableLayouts (VolumeType::Enum type = VolumeType::Unknown);
		virtual uint64 GetDataOffset (uint64 volumeHostSize) const = 0;
		virtual uint64 GetDataSize (uint64 volumeHostSize) const = 0;
		virtual shared_ptr <VolumeHeader> GetHeader ();
		virtual int GetHeaderOffset () const { return HeaderOffset; } // Positive value: offset from the start of host, negative: offset from the end
		virtual uint32 GetHeaderSize () const { return HeaderSize; }
		virtual EncryptionAlgorithmList GetSupportedEncryptionAlgorithms () const { return SupportedEncryptionAlgorithms; }
		virtual EncryptionModeList GetSupportedEncryptionModes () const { return SupportedEncryptionModes; }
		virtual VolumeType::Enum GetType () const { return Type; }

	protected:
		VolumeLayout ();

		EncryptionAlgorithmList SupportedEncryptionAlgorithms;
		EncryptionModeList SupportedEncryptionModes;

		int HeaderOffset;
		uint32 HeaderSize;
		VolumeType::Enum Type;

		shared_ptr <VolumeHeader> Header;

	private:
		VolumeLayout (const VolumeLayout &);
		VolumeLayout &operator= (const VolumeLayout &);
	};

	class VolumeLayoutV1Normal : public VolumeLayout
	{
	public:
		VolumeLayoutV1Normal ();
		virtual ~VolumeLayoutV1Normal () { }

		virtual uint64 GetDataOffset (uint64 volumeHostSize) const;
		virtual uint64 GetDataSize (uint64 volumeHostSize) const;

	private:
		VolumeLayoutV1Normal (const VolumeLayoutV1Normal &);
		VolumeLayoutV1Normal &operator= (const VolumeLayoutV1Normal &);
	};

	class VolumeLayoutV1Hidden : public VolumeLayout
	{
	public:
		VolumeLayoutV1Hidden ();
		virtual ~VolumeLayoutV1Hidden () { }

		virtual uint64 GetDataOffset (uint64 volumeHostSize) const;
		virtual uint64 GetDataSize (uint64 volumeHostSize) const;

	private:
		VolumeLayoutV1Hidden (const VolumeLayoutV1Hidden &);
		VolumeLayoutV1Hidden &operator= (const VolumeLayoutV1Hidden &);
	};
}

#endif // TC_HEADER_Volume_VolumeLayout
