/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <fstream>
#include <iomanip>
#include <mntent.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include "CoreLinux.h"
#include "Platform/TextReader.h"
#include "Volume/EncryptionModeXTS.h"
#include "Driver/Fuse/FuseService.h"
#include "Core/Unix/CoreServiceProxy.h"

namespace TrueCrypt
{
	CoreLinux::CoreLinux ()
	{
	}

	CoreLinux::~CoreLinux ()
	{
	}

	DevicePath CoreLinux::AttachFileToLoopDevice (const FilePath &filePath) const
	{
		list <string> loopPaths;
		loopPaths.push_back ("/dev/loop");
		loopPaths.push_back ("/dev/loop/");
		loopPaths.push_back ("/dev/.static/dev/loop");

		for (int devIndex = 0; devIndex < 256; devIndex++)
		{
			string loopDev;
			foreach (const string &loopPath, loopPaths)
			{
				loopDev = loopPath + StringConverter::ToSingle (devIndex);
				if (FilesystemPath (loopDev).IsBlockDevice())
					break;
			}

			if (loopDev.empty())
				continue;

			list <string> args;
			args.push_back ("--");
			args.push_back (loopDev);
			args.push_back (filePath);

			try
			{
				Process::Execute ("losetup", args);
				return loopDev;
			}
			catch (ExecutedProcessFailed&) { }
		}

		throw NoLoopbackDeviceAvailable (SRC_POS);
	}

	void CoreLinux::DetachLoopDevice (const DevicePath &devicePath) const
	{
		list <string> args;
		args.push_back ("-d");
		args.push_back (devicePath);

		for (int t = 0; true; t++)
		{
			try
			{
				Process::Execute ("losetup", args);
				break;
			}
			catch (ExecutedProcessFailed&)
			{
				if (t > 5)
					throw;
				Thread::Sleep (200);
			}
		}
	}

	void CoreLinux::DismountNativeVolume (shared_ptr <VolumeInfo> mountedVolume) const
	{
		string devPath = mountedVolume->VirtualDevice;

		if (devPath.find ("/dev/mapper/truecrypt") != 0)
			throw NotApplicable (SRC_POS);

		size_t devCount = 0;
		while (FilesystemPath (devPath).IsBlockDevice())
		{
			list <string> dmsetupArgs;
			dmsetupArgs.push_back ("remove");
			dmsetupArgs.push_back (StringConverter::Split (devPath, "/").back());

			Process::Execute ("dmsetup", dmsetupArgs);

			devPath = string (mountedVolume->VirtualDevice) + "_" + StringConverter::ToSingle (devCount++);
		}
	}

	HostDeviceList CoreLinux::GetHostDevices (bool pathListOnly) const
	{
		HostDeviceList devices;
		TextReader tr ("/proc/partitions");

		string line;
		while (tr.ReadLine (line))
		{
			vector <string> fields = StringConverter::Split (line);
			
			if (fields.size() != 4
				|| fields[3].find ("loop") != string::npos	// skip loop devices
				|| fields[2] == "1"							// skip extended partitions
				)
				continue;

			try
			{
				StringConverter::ToUInt32 (fields[0]);
			}
			catch (...)
			{
				continue;
			}

			try
			{
				make_shared_auto (HostDevice, hostDevice);

				hostDevice->Path = string (fields[3].find ("/dev/") == string::npos ? "/dev/" : "") + fields[3];

				if (!pathListOnly)
				{
					hostDevice->Size = StringConverter::ToUInt64 (fields[2]) * 1024;
					hostDevice->MountPoint = GetDeviceMountPoint (hostDevice->Path);
					hostDevice->SystemNumber = 0;
				}

				try
				{
					StringConverter::GetTrailingNumber (fields[3]);
					if (devices.size() > 0)
					{
						HostDevice &prevDev = **--devices.end();
						if (string (hostDevice->Path).find (prevDev.Path) == 0)
						{
							prevDev.Partitions.push_back (hostDevice);
							continue;
						}
					}
				}
				catch (...) { }

				devices.push_back (hostDevice);
				continue;
			}
			catch (...)
			{
				continue;
			}
		}

		return devices;
	}

	MountedFilesystemList CoreLinux::GetMountedFilesystems (const DevicePath &devicePath, const DirectoryPath &mountPoint) const
	{
		MountedFilesystemList mountedFilesystems;

		FILE *mtab = fopen ("/etc/mtab", "r");

		if (!mtab)
			mtab = fopen ("/proc/mounts", "r");

		throw_sys_sub_if (!mtab, "/proc/mounts");
		finally_do_arg (FILE *, mtab, { fclose (finally_arg); });

		static Mutex mutex;
		ScopeLock sl (mutex);

		struct mntent *entry;
		while ((entry = getmntent (mtab)) != nullptr)
		{
			make_shared_auto (MountedFilesystem, mf);

			if (entry->mnt_fsname)
				mf->Device = DevicePath (entry->mnt_fsname);
			else
				continue;

			if (entry->mnt_dir)
				mf->MountPoint = DirectoryPath (entry->mnt_dir);

			if ((devicePath.IsEmpty() || devicePath == mf->Device) && (mountPoint.IsEmpty() || mountPoint == mf->MountPoint))
				mountedFilesystems.push_back (mf);
		}

		return mountedFilesystems;
	}

	void CoreLinux::MountFilesystem (const DevicePath &devicePath, const DirectoryPath &mountPoint, const string &filesystemType, bool readOnly, const string &systemMountOptions) const
	{
		try
		{
			stringstream userMountOptions;
			userMountOptions << "uid=" << GetRealUserId() << ",gid=" << GetRealGroupId() << ",umask=077" << (!systemMountOptions.empty() ? "," : "");
			
			CoreUnix::MountFilesystem (devicePath, mountPoint, filesystemType, readOnly, userMountOptions.str() + systemMountOptions);
		}
		catch (...)
		{
			CoreUnix::MountFilesystem (devicePath, mountPoint, filesystemType, readOnly, systemMountOptions);
		}
	}

	void CoreLinux::MountVolumeNative (shared_ptr <Volume> volume, MountOptions &options, const DirectoryPath &auxMountPoint) const
	{
		if (options.NoKernelCrypto
			|| typeid (*volume->GetEncryptionMode()) != typeid (EncryptionModeXTS)
			|| volume->GetProtectionType() == VolumeProtection::HiddenVolumeReadOnly)
		{
			throw NotApplicable (SRC_POS);
		}

		utsname unameData;
		if (uname (&unameData) != -1)
		{
			vector <string> osVersion = StringConverter::Split (unameData.release, ".-");
			if (osVersion.size() >= 3
				&& osVersion[0] == "2" && osVersion[1] == "6" && StringConverter::ToUInt32 (osVersion[2]) < 24)
			{
				throw NotApplicable (SRC_POS);
			}
		}

		// Load device mapper kernel module
		list <string> execArgs;
		execArgs.push_back ("dm_mod");
		try
		{
			Process::Execute ("modprobe", execArgs);
		}
		catch (...) { }

		bool loopDevAttached = false;
		bool nativeDevCreated = false;
		bool filesystemMounted = false;

		// Attach volume to loopback device if required
		VolumePath volumePath = volume->GetPath();
		if (!volumePath.IsDevice() || (options.Path->IsDevice() && volume->GetFile()->GetDeviceSectorSize() != ENCRYPTION_DATA_UNIT_SIZE))
		{
			volumePath = AttachFileToLoopDevice (volumePath);
			loopDevAttached = true;
		}

		string nativeDevPath;

		try
		{
			// Create virtual device using device mapper
			size_t nativeDevCount = 0;
			size_t secondaryKeyOffset = volume->GetEncryptionMode()->GetKey().Size();
			size_t cipherCount = volume->GetEncryptionAlgorithm()->GetCiphers().size();

			foreach_reverse_ref (const Cipher &cipher, volume->GetEncryptionAlgorithm()->GetCiphers())
			{
				stringstream dmCreateArgs;
				dmCreateArgs << "0 " << volume->GetSize() / ENCRYPTION_DATA_UNIT_SIZE << " crypt ";

				dmCreateArgs << StringConverter::ToLower (StringConverter::ToSingle (cipher.GetName())) << "-xts-plain ";

				size_t keyArgOffset = dmCreateArgs.str().size();
				dmCreateArgs << setw (cipher.GetKeySize() * 4) << 0 << setw (0);

				uint64 startSector = volume->GetLayout()->GetDataOffset (volume->GetHostSize()) / ENCRYPTION_DATA_UNIT_SIZE;

				dmCreateArgs << ' ' << startSector << ' ';
				if (nativeDevCount == 0)
					dmCreateArgs << string (volumePath) << ' ' << startSector;
				else
					dmCreateArgs << nativeDevPath << " 0";

				SecureBuffer dmCreateArgsBuf (dmCreateArgs.str().size());
				dmCreateArgsBuf.CopyFrom (ConstBufferPtr ((byte *) dmCreateArgs.str().c_str(), dmCreateArgs.str().size()));

				const SecureBuffer &cipherKey = cipher.GetKey();
				secondaryKeyOffset -= cipherKey.Size();
				ConstBufferPtr secondaryKey = volume->GetEncryptionMode()->GetKey().GetRange (secondaryKeyOffset, cipherKey.Size());

				SecureBuffer hexStr (3);
				for (size_t i = 0; i < cipherKey.Size(); ++i)
				{
					sprintf ((char *) hexStr.Ptr(), "%02x", (int) cipherKey[i]);
					dmCreateArgsBuf.GetRange (keyArgOffset + i * 2, 2).CopyFrom (hexStr.GetRange (0, 2));

					sprintf ((char *) hexStr.Ptr(), "%02x", (int) secondaryKey[i]);
					dmCreateArgsBuf.GetRange (keyArgOffset + cipherKey.Size() * 2 + i * 2, 2).CopyFrom (hexStr.GetRange (0, 2));
				}

				stringstream nativeDevName;
				nativeDevName << "truecrypt" << options.SlotNumber;
				
				if (nativeDevCount != cipherCount - 1)
					nativeDevName << "_" << cipherCount - nativeDevCount - 2;
				
				nativeDevPath = string ("/dev/mapper/") + nativeDevName.str();

				execArgs.clear();
				execArgs.push_back ("create");
				execArgs.push_back (nativeDevName.str());

				Process::Execute ("dmsetup", execArgs, -1, nullptr, &dmCreateArgsBuf);
				
				nativeDevCreated = true;
				++nativeDevCount;
			}

			// Mount filesystem
			if (!options.NoFilesystem && options.MountPoint && !options.MountPoint->IsEmpty())
			{
				MountFilesystem (nativeDevPath, *options.MountPoint,
					StringConverter::ToSingle (options.FilesystemType),
					options.Protection == VolumeProtection::ReadOnly,
					StringConverter::ToSingle (options.FilesystemOptions));

				filesystemMounted = true;
			}

			FuseService::SendAuxDeviceInfo (auxMountPoint, nativeDevPath, volumePath);
		}
		catch (...)
		{
			try
			{
				if (filesystemMounted)
					DismountFilesystem (*options.MountPoint, true);
			}
			catch (...) { }

			try
			{
				if (nativeDevCreated)
				{
					make_shared_auto (VolumeInfo, vol);
					vol->VirtualDevice = nativeDevPath;
					DismountNativeVolume (vol);
				}
			}
			catch (...) { }

			try
			{
				if (loopDevAttached)
					DetachLoopDevice (volumePath);
			}
			catch (...) { }

			throw;
		}
	}

	auto_ptr <CoreBase> Core (new CoreServiceProxy <CoreLinux>);
	auto_ptr <CoreBase> CoreDirect (new CoreLinux);
}
