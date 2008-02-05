/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Main_CommandInterface
#define TC_HEADER_Main_CommandInterface

#include "System.h"
#include "Main.h"
#include "Volume/VolumeInfo.h"
#include "Core/MountOptions.h"
#include "UserPreferences.h"
#include "UserInterfaceType.h"

namespace TrueCrypt
{
	struct CommandId
	{
		enum Enum
		{
			None,
			AutoMountDevices,
			AutoMountDevicesFavorites,
			AutoMountFavorites,
			ChangePassword,
			DismountVolumes,
			DisplayVersion,
			Help,
			ListVolumes,
			MountVolume,
			Test
		};
	};

	struct CommandLineInterface
	{
	public:
		CommandLineInterface (wxCmdLineParser &parser, UserInterfaceType::Enum interfaceType);
		virtual ~CommandLineInterface ();


		CommandId::Enum ArgCommand;
		bool ArgForce;
		shared_ptr <KeyfileList> ArgKeyfiles;
		shared_ptr <DirectoryPath> ArgMountPoint;
		shared_ptr <KeyfileList> ArgNewKeyfiles;
		shared_ptr <VolumePassword> ArgNewPassword;
		shared_ptr <VolumePassword> ArgPassword;
		VolumeInfoList ArgVolumes;
		shared_ptr <VolumePath> ArgVolumePath;
		MountOptions ArgMountOptions;

		bool StartBackgroundTask;
		UserPreferences Preferences;

	protected:
		void CheckCommandSingle () const;
		shared_ptr <KeyfileList> ToKeyfileList (const wxString &arg) const;
		VolumeInfoList GetMountedVolumes (const wxString &filter) const;

	private:
		CommandLineInterface (const CommandLineInterface &);
		CommandLineInterface &operator= (const CommandLineInterface &);
	};

	extern auto_ptr <CommandLineInterface> CmdLine;
}

#endif // TC_HEADER_Main_CommandInterface
