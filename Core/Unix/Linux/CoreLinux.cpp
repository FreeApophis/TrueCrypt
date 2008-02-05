/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <fstream>
#include <mntent.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include "CoreLinux.h"
#include "Platform/TextReader.h"
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
		MountedFilesystemList mountedFilesystems = GetMountedFilesystems();

		for (int devIndex = 0; devIndex < 256; devIndex++)
		{
			stringstream loopDev;
			loopDev << "/dev/loop" << devIndex;

			try
			{
				if (!FilesystemPath (loopDev.str()).IsBlockDevice())
					throw false;
			}
			catch (...)
			{
				loopDev.str ("");
				loopDev << "/dev/loop/" << devIndex;

				try
				{
					if (!FilesystemPath (loopDev.str()).IsBlockDevice())
						continue;
				}
				catch (...)
				{
					continue;
				}
			}

			try
			{
				foreach_ref (const MountedFilesystem &mf, mountedFilesystems)
				{
					if (mf.Device == loopDev.str())
						throw false;
				}
			}
			catch (bool)
			{
				continue;
			}

			list <string> args;
			args.push_back ("--");
			args.push_back (loopDev.str());
			args.push_back (filePath);

			try
			{
				Process::Execute ("losetup", args);
				return loopDev.str();
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
			stringstream uid;
			uid << "uid=" << GetRealUserId() << ",gid=" << GetRealGroupId() << ",umask=077" << (!systemMountOptions.empty() ? "," : "");
			
			CoreUnix::MountFilesystem (devicePath, mountPoint, filesystemType, readOnly, uid.str() + systemMountOptions);
		}
		catch (...)
		{
			CoreUnix::MountFilesystem (devicePath, mountPoint, filesystemType, readOnly, systemMountOptions);
		}
	}

	auto_ptr <CoreBase> Core (new CoreServiceProxy <CoreLinux>);
	auto_ptr <CoreBase> CoreDirect (new CoreLinux);
}
