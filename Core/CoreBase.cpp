/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <set>

#ifdef TC_UNIX
#include "Core.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

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

	void CoreBase::BackupVolumeHeaders (const VolumePath &volumePath, const FilePath &backupFilePath) const
	{
		File volumeFile, backupFile;
		backupFile.Open (backupFilePath, File::CreateWrite);

		{
#ifdef TC_UNIX
			UserId origDeviceOwner;
			origDeviceOwner.SystemId = (uid_t) -1;

			if (!HasAdminPrivileges() && volumePath.IsDevice())
			{
				// Temporarily take ownership of the host device
				struct stat statData;
				throw_sys_if (stat (string (volumePath).c_str(), &statData) == -1);

				UserId owner;
				owner.SystemId = getuid();
				SetFileOwner (volumePath, owner);
				origDeviceOwner.SystemId = statData.st_uid;
			}

			finally_do_arg2 (VolumePath, volumePath, UserId, origDeviceOwner,
				{
					if (finally_arg2.SystemId != -1)
						Core->SetFileOwner (finally_arg, finally_arg2);
				}
			);
#endif
			volumeFile.Open (volumePath, File::OpenRead);
		}

		foreach_ref (const VolumeLayout &layout, VolumeLayout::GetAvailableLayouts())
		{
			SecureBuffer header (layout.GetHeaderSize());
			
			int offset = layout.GetHeaderOffset();
			if (offset >= 0)
				volumeFile.SeekAt (offset);
			else
				volumeFile.SeekEnd (offset);

			volumeFile.Read (header);
			backupFile.Write (header);
		}
	}

	void CoreBase::ChangePassword (shared_ptr <Volume> openVolume, shared_ptr <VolumePassword> newPassword, shared_ptr <KeyfileList> newKeyfiles, shared_ptr <Pkcs5Kdf> newPkcs5Kdf) const
	{
		if ((!newPassword || newPassword->Size() < 1) && (!newKeyfiles || newKeyfiles->empty()))
			throw PasswordEmpty (SRC_POS);

		if (newPassword)
			newPassword->CheckPortability();
		
		if (!newPkcs5Kdf)
			newPkcs5Kdf = openVolume->GetPkcs5Kdf();

		RandomNumberGenerator::Start();
		RandomNumberGenerator::SetHash (newPkcs5Kdf->GetHash());

		SecureBuffer newSalt (openVolume->GetSaltSize());
		SecureBuffer newHeaderKey (VolumeHeader::GetLargestSerializedKeySize());

		shared_ptr <VolumePassword> password (Keyfile::ApplyListToPassword (newKeyfiles, newPassword));

		for (int i = 1; i <= SecureWipePassCount; i++)
		{
			if (i == SecureWipePassCount)
				RandomNumberGenerator::GetData (newSalt);
			else
				RandomNumberGenerator::GetDataFast (newSalt);

			newPkcs5Kdf->DeriveKey (newHeaderKey, *password, newSalt);

			openVolume->ReEncryptHeader (newSalt, newHeaderKey, newPkcs5Kdf);
			openVolume->GetFile()->Flush();
		}

		RandomNumberGenerator::Stop();
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

	shared_ptr <Volume> CoreBase::OpenVolume (shared_ptr <VolumePath> volumePath, bool preserveTimestamps, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, VolumeProtection::Enum protection, shared_ptr <VolumePassword> protectionPassword, shared_ptr <KeyfileList> protectionKeyfiles, bool sharedAccessAllowed, VolumeType::Enum volumeType) const
	{
		make_shared_auto (Volume, volume);
		volume->Open (*volumePath, preserveTimestamps, password, keyfiles, protection, protectionPassword, protectionKeyfiles, sharedAccessAllowed, volumeType);
		return volume;
	}
	
	void CoreBase::RestoreVolumeHeaders (const VolumePath &volumePath, VolumeType::Enum volumeType, const FilePath &backupFilePath) const
	{
		File volumeFile, backupFile;
		backupFile.Open (backupFilePath, File::OpenRead);

		{
#ifdef TC_UNIX
			UserId origDeviceOwner;
			origDeviceOwner.SystemId = (uid_t) -1;

			if (!HasAdminPrivileges() && volumePath.IsDevice())
			{
				// Temporarily take ownership of the host device
				struct stat statData;
				throw_sys_if (stat (string (volumePath).c_str(), &statData) == -1);

				UserId owner;
				owner.SystemId = getuid();
				SetFileOwner (volumePath, owner);
				origDeviceOwner.SystemId = statData.st_uid;
			}

			finally_do_arg2 (VolumePath, volumePath, UserId, origDeviceOwner,
				{
					if (finally_arg2.SystemId != (uid_t) -1)
						Core->SetFileOwner (finally_arg, finally_arg2);
				}
			);
#endif
			volumeFile.Open (volumePath, File::OpenWrite);
		}

		shared_ptr <VolumeLayout> layout = VolumeLayout::GetAvailableLayouts (volumeType).front();

		SecureBuffer header (layout->GetHeaderSize());
		backupFile.ReadAt (header, volumeType == VolumeType::Hidden ? layout->GetHeaderSize() : 0);

		int offset = layout->GetHeaderOffset();
		if (offset >= 0)
			volumeFile.SeekAt (offset);
		else
			volumeFile.SeekEnd (offset);

		volumeFile.Write (header);
	}
}
