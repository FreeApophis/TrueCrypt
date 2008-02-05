/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <fstream>
#include <stdio.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include "CoreMacOSX.h"
#include "Driver/Fuse/FuseService.h"
#include "Core/Unix/CoreServiceProxy.h"

namespace TrueCrypt
{
	CoreMacOSX::CoreMacOSX ()
	{
	}

	CoreMacOSX::~CoreMacOSX ()
	{
	}

	void CoreMacOSX::DismountVolume (shared_ptr <VolumeInfo> mountedVolume, bool ignoreOpenFiles)
	{
		if (!mountedVolume->LoopDevice.IsEmpty() && mountedVolume->LoopDevice.IsBlockDevice())
		{
			list <string> args;
			args.push_back ("detach");
			args.push_back (mountedVolume->LoopDevice);

			if (ignoreOpenFiles)
				args.push_back ("-force");

			try
			{
				Process::Execute ("hdiutil", args);
			}
			catch (ExecutedProcessFailed &e)
			{
				if (e.GetErrorOutput().find("49153") != string::npos)
					throw MountedVolumeInUse (SRC_POS);
				throw;
			}
		}

		list <string> args;
		args.push_back ("--");
		args.push_back (mountedVolume->AuxMountPoint);

		for (int t = 0; true; t++)
		{
			try
			{
				Process::Execute ("umount", args);
				break;
			}
			catch (ExecutedProcessFailed&)
			{
				if (t > 10)
					throw;
				Thread::Sleep (200);
			}
		}

		try
		{
			mountedVolume->AuxMountPoint.Delete();
		}
		catch (...)	{ }
	}

	void CoreMacOSX::MountAuxVolumeImage (const DirectoryPath &auxMountPoint, const MountOptions &options) const
	{
		string volImage = string (auxMountPoint) + FuseService::GetVolumeImagePath();

		list <string> args;
		args.push_back ("attach");
		args.push_back (volImage);
		args.push_back ("-plist");

		if (!options.NoFilesystem && options.MountPoint && !options.MountPoint->IsEmpty())
		{
			args.push_back ("-mount");
			args.push_back ("required");

			// Let the system specify mount point except when the user specified a non-default one
			if (string (*options.MountPoint).find (GetDefaultMountPointPrefix()) != 0)
			{
				args.push_back ("-mountpoint");
				args.push_back (*options.MountPoint);
			}
		}
		else
			args.push_back ("-nomount");

		if (options.Protection == VolumeProtection::ReadOnly)
			args.push_back ("-readonly");

		string xml = Process::Execute ("hdiutil", args);

		size_t p = xml.find ("<key>dev-entry</key>");
		if (p == string::npos)
			throw ParameterIncorrect (SRC_POS);

		p = xml.find ("<string>", p);
		if (p == string::npos)
			throw ParameterIncorrect (SRC_POS);
		p += 8;

		size_t e = xml.find ("</string>", p);
		if (e == string::npos)
			throw ParameterIncorrect (SRC_POS);

		DevicePath loopDev = StringConverter::Trim (xml.substr (p, e - p));

		try
		{
			FuseService::SendLoopDevice (auxMountPoint, loopDev);
		}
		catch (...)
		{
			try
			{
				list <string> args;
				args.push_back ("detach");
				args.push_back (volImage);
				args.push_back ("-force");

				Process::Execute ("hdiutil", args);
			}
			catch (ExecutedProcessFailed&) { }
			throw;
		}
	}

	auto_ptr <CoreBase> Core (new CoreServiceProxy <CoreMacOSX>);
	auto_ptr <CoreBase> CoreDirect (new CoreMacOSX);
}
