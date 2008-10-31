/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.6 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <set>

#include "CoreBase.h"
#include "RandomNumberGenerator.h"
#include "Volume/Volume.h"

namespace TrueCrypt
{
	CoreBase::CoreBase ()
		: DeviceChangeInProgress (false)
	{
	}

	CoreBase::~CoreBase ()
	{
	}

	void CoreBase::ChangePassword (shared_ptr <Volume> openVolume, shared_ptr <VolumePassword> newPassword, shared_ptr <KeyfileList> newKeyfiles, shared_ptr <Pkcs5Kdf> newPkcs5Kdf) const
	{
		if ((!newPassword || newPassword->Size() < 1) && (!newKeyfiles || newKeyfiles->empty()))
			throw PasswordEmpty (SRC_POS);

		if (!newPkcs5Kdf)
			newPkcs5Kdf = openVolume->GetPkcs5Kdf();

		if (openVolume->GetHeader()->GetFlags() & TC_HEADER_FLAG_ENCRYPTED_SYSTEM)
			throw EncryptedSystemRequired (SRC_POS);

		RandomNumberGenerator::Start();
		finally_do ({ RandomNumberGenerator::Stop(); });

		RandomNumberGenerator::SetHash (newPkcs5Kdf->GetHash());

		SecureBuffer newSalt (openVolume->GetSaltSize());
		SecureBuffer newHeaderKey (VolumeHeader::GetLargestSerializedKeySize());

		shared_ptr <VolumePassword> password (Keyfile::ApplyListToPassword (newKeyfiles, newPassword));

		bool backupHeader = false;
		while (true)
		{
			for (int i = 1; i <= SecureWipePassCount; i++)
			{
				if (i == SecureWipePassCount)
					RandomNumberGenerator::GetData (newSalt);
				else
					RandomNumberGenerator::GetDataFast (newSalt);

				newPkcs5Kdf->DeriveKey (newHeaderKey, *password, newSalt);

				openVolume->ReEncryptHeader (backupHeader, newSalt, newHeaderKey, newPkcs5Kdf);
				openVolume->GetFile()->Flush();
			}

			if (!openVolume->GetLayout()->HasBackupHeader() || backupHeader)
				break;

			backupHeader = true;
		}
	}
		
	void CoreBase::ChangePassword (shared_ptr <VolumePath> volumePath, bool preserveTimestamps, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, shared_ptr <VolumePassword> newPassword, shared_ptr <KeyfileList> newKeyfiles, shared_ptr <Pkcs5Kdf> newPkcs5Kdf) const
	{
		shared_ptr <Volume> volume = OpenVolume (volumePath, preserveTimestamps, password, keyfiles);
		ChangePassword (volume, newPassword, newKeyfiles, newPkcs5Kdf);
	}

	void CoreBase::CoalesceSlotNumberAndMountPoint (MountOptions &options) const
	{
		if (options.SlotNumber < GetFirstSlotNumber())
		{
			if (options.MountPoint && !options.MountPoint->IsEmpty())
				options.SlotNumber = MountPointToSlotNumber (*options.MountPoint);
			else
				options.SlotNumber = GetFirstFreeSlotNumber();
		}

		if (!IsSlotNumberAvailable (options.SlotNumber))
#ifdef TC_WINDOWS
			throw DriveLetterUnavailable (SRC_POS);
#else
			throw VolumeSlotUnavailable (SRC_POS);
#endif
		if (!options.NoFilesystem && (!options.MountPoint || options.MountPoint->IsEmpty()))
			options.MountPoint.reset (new DirectoryPath (SlotNumberToMountPoint (options.SlotNumber)));
	}

	void CoreBase::CreateKeyfile (const FilePath &keyfilePath) const
	{
		RandomNumberGenerator::Start();
		finally_do ({ RandomNumberGenerator::Stop(); });

		SecureBuffer keyfileBuffer (VolumePassword::MaxSize);
		RandomNumberGenerator::GetData (keyfileBuffer);

		File keyfile;
		keyfile.Open (keyfilePath, File::CreateWrite);
		keyfile.Write (keyfileBuffer);
	}

	VolumeSlotNumber CoreBase::GetFirstFreeSlotNumber (VolumeSlotNumber startFrom) const
	{
		if (startFrom < GetFirstSlotNumber())
			startFrom = GetFirstSlotNumber();

		set <VolumeSlotNumber> usedSlotNumbers;

		foreach_ref (const VolumeInfo &volume, GetMountedVolumes())
			usedSlotNumbers.insert (volume.SlotNumber);

		for (VolumeSlotNumber slotNumber = startFrom; slotNumber <= GetLastSlotNumber(); ++slotNumber)
		{
			if (usedSlotNumbers.find (slotNumber) == usedSlotNumbers.end()
				&& IsMountPointAvailable (SlotNumberToMountPoint (slotNumber)))
				return slotNumber;
		}
#ifdef TC_WINDOWS
		throw DriveLetterUnavailable (SRC_POS);
#else
		throw VolumeSlotUnavailable (SRC_POS);
#endif
	}

	shared_ptr <VolumeInfo> CoreBase::GetMountedVolume (const VolumePath &volumePath) const
	{
		VolumeInfoList volumes = GetMountedVolumes (volumePath);
		if (volumes.empty())
			return shared_ptr <VolumeInfo> ();
		else
			return volumes.front();
	}

	shared_ptr <VolumeInfo> CoreBase::GetMountedVolume (VolumeSlotNumber slot) const
	{
		foreach (shared_ptr <VolumeInfo> volume, GetMountedVolumes())
		{
			if (volume->SlotNumber == slot)
				return volume;
		}

		return shared_ptr <VolumeInfo> ();
	}

	bool CoreBase::IsSlotNumberAvailable (VolumeSlotNumber slotNumber) const
	{
		if (!IsMountPointAvailable (SlotNumberToMountPoint (slotNumber)))
			return false;

		foreach_ref (const VolumeInfo &volume, GetMountedVolumes())
		{
			if (volume.SlotNumber == slotNumber)
				return false;
		}

		return true;
	}

	bool CoreBase::IsVolumeMounted (const VolumePath &volumePath) const
	{
		return GetMountedVolume (volumePath);
	}

	shared_ptr <Volume> CoreBase::OpenVolume (shared_ptr <VolumePath> volumePath, bool preserveTimestamps, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, VolumeProtection::Enum protection, shared_ptr <VolumePassword> protectionPassword, shared_ptr <KeyfileList> protectionKeyfiles, bool sharedAccessAllowed, VolumeType::Enum volumeType, bool useBackupHeaders, bool partitionInSystemEncryptionScope) const
	{
		make_shared_auto (Volume, volume);
		volume->Open (*volumePath, preserveTimestamps, password, keyfiles, protection, protectionPassword, protectionKeyfiles, sharedAccessAllowed, volumeType, useBackupHeaders, partitionInSystemEncryptionScope);
		return volume;
	}
	
	void CoreBase::RandomizeEncryptionAlgorithmKey (shared_ptr <EncryptionAlgorithm> encryptionAlgorithm) const
	{
		SecureBuffer eaKey (encryptionAlgorithm->GetKeySize());
		RandomNumberGenerator::GetData (eaKey);
		encryptionAlgorithm->SetKey (eaKey);

		SecureBuffer modeKey (encryptionAlgorithm->GetMode()->GetKeySize());
		RandomNumberGenerator::GetData (modeKey);
		encryptionAlgorithm->GetMode()->SetKey (modeKey);
	}

	void CoreBase::ReEncryptVolumeHeaderWithNewSalt (const BufferPtr &newHeaderBuffer, shared_ptr <VolumeHeader> header, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles) const
	{
		shared_ptr <Pkcs5Kdf> pkcs5Kdf = header->GetPkcs5Kdf();

		RandomNumberGenerator::SetHash (pkcs5Kdf->GetHash());

		SecureBuffer newSalt (header->GetSaltSize());
		SecureBuffer newHeaderKey (VolumeHeader::GetLargestSerializedKeySize());

		shared_ptr <VolumePassword> passwordKey (Keyfile::ApplyListToPassword (keyfiles, password));

		RandomNumberGenerator::GetData (newSalt);
		pkcs5Kdf->DeriveKey (newHeaderKey, *passwordKey, newSalt);

		header->EncryptNew (newHeaderBuffer, newSalt, newHeaderKey, pkcs5Kdf);
	}
}
