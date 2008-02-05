/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Volume_VolumeHeader
#define TC_HEADER_Volume_VolumeHeader

#include "Common/Tcdefs.h"
#include "Platform/Platform.h"
#include "Volume/EncryptionAlgorithm.h"
#include "Volume/EncryptionMode.h"
#include "Volume/Keyfile.h"
#include "Volume/VolumePassword.h"
#include "Volume/Pkcs5Kdf.h"
#include "Version.h"

/* Volume header v3 structure: */
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Salt
// Encrypted:
// 64		4		ASCII string 'TRUE'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC-32 checksum of the (decrypted) bytes 256-511
// 76		8		Volume creation time
// 84		8		Header creation time
// 92		8		Size of hidden volume in bytes (0 = normal volume)
// 100		8		Size of the volume in bytes (identical with field 92 for hidden volumes)
// 108		8		Start byte offset of the encrypted area of the volume
// 116		8		Size of the encrypted area of the volume in bytes
// 124		132		Reserved (set to zero)
// 256		256		Concatenated primary master key(s) and secondary master key(s) (XTS mode)


/* Deprecated/legacy volume header v2 structure (used before TrueCrypt 5.0): */
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Salt
// Encrypted:
// 64		4		ASCII string 'TRUE'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC-32 checksum of the (decrypted) bytes 256-511
// 76		8		Volume creation time
// 84		8		Header creation time
// 92		8		Size of hidden volume in bytes (0 = normal volume)
// 100		156		Reserved (set to zero)
// 256		32		For LRW (deprecated/legacy), secondary key
//					For CBC (deprecated/legacy), data used to generate IV and whitening values
// 288		224		Master key(s)

namespace TrueCrypt
{
	typedef uint64 VolumeTime;

	struct VolumeType
	{
		enum Enum
		{
			Unknown,
			Normal,
			Hidden
		};
	};

	struct VolumeHeaderCreationOptions
	{
		ConstBufferPtr DataKey;
		shared_ptr <EncryptionAlgorithm> EA;
		shared_ptr <Pkcs5Kdf> Kdf;
		ConstBufferPtr HeaderKey;
		ConstBufferPtr Salt;
		uint64 VolumeSize;
		VolumeType::Enum Type;
	};

	class VolumeHeader
	{
	public:
		VolumeHeader (uint32 HeaderSize);
		virtual ~VolumeHeader ();

		void Create (const BufferPtr &headerBuffer, VolumeHeaderCreationOptions &options);
		bool Decrypt (const ConstBufferPtr &encryptedData, const VolumePassword &password, const EncryptionAlgorithmList &encryptionAlgorithms, const EncryptionModeList &encryptionModes);
		void EncryptNew (const BufferPtr &newHeaderBuffer, const ConstBufferPtr &newSalt, const ConstBufferPtr &newHeaderKey, shared_ptr <Pkcs5Kdf> newPkcs5Kdf);
		shared_ptr <EncryptionAlgorithm> GetEncryptionAlgorithm () const { return EA; }
		VolumeTime GetHeaderCreationTime () const { return HeaderCreationTime; }
		uint64 GetHiddenVolumeDataSize () const { return HiddenVolumeDataSize; }
		static size_t GetLargestSerializedKeySize ();
		shared_ptr <Pkcs5Kdf> GetPkcs5Kdf () const { return Pkcs5; }
		size_t GetSectorSize () const { return 512; }
		static uint32 GetSaltSize () { return SaltSize; }
		uint64 GetVolumeDataSize () const { return VolumeDataSize; }
		VolumeTime GetVolumeCreationTime () const { return VolumeCreationTime; }

	protected:
		bool Deserialize (const ConstBufferPtr &header, shared_ptr <EncryptionAlgorithm> &ea, shared_ptr <EncryptionMode> &mode);
		template <typename T> T DeserializeEntry (const ConstBufferPtr &header, size_t &offset) const;
		void Serialize (const BufferPtr &header) const;
		template <typename T> void SerializeEntry (const T &entry, const BufferPtr &header, size_t &offset) const;

		uint32 HeaderSize;

		static const uint16 CurrentHeaderVersion = VOLUME_HEADER_VERSION;
		static const uint16 CurrentRequiredMinProgramVersion = VOL_REQ_PROG_VERSION;
		static const uint16 MinAllowedHeaderVersion = 1;

		static const int SaltOffset = 0;
		static const uint32 SaltSize = 64;

		static const int EncryptedHeaderDataOffset = SaltOffset + SaltSize;
		uint32 EncryptedHeaderDataSize;

		static const uint32 LegacyEncryptionModeKeyAreaSize = 32;
		static const int DataKeyAreaMaxSize = 256;
		static const uint32 DataAreaKeyOffset = DataKeyAreaMaxSize - EncryptedHeaderDataOffset;

		shared_ptr <EncryptionAlgorithm> EA;
		shared_ptr <Pkcs5Kdf> Pkcs5;

		uint16 HeaderVersion;
		uint16 RequiredMinProgramVersion;
		uint32 VolumeKeyAreaCrc32;

		VolumeTime VolumeCreationTime;
		VolumeTime HeaderCreationTime;

		VolumeType::Enum mVolumeType;
		uint64 HiddenVolumeDataSize;
		uint64 VolumeDataSize;
		uint64 EncryptedAreaStart;
		uint64 EncryptedAreaLength;

		SecureBuffer DataAreaKey;

	private:
		VolumeHeader (const VolumeHeader &);
		VolumeHeader &operator= (const VolumeHeader &);
	};
}

#endif // TC_HEADER_Volume_VolumeHeader
