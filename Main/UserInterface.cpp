/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "System.h"
#include <set>
#include <typeinfo>
#include <wx/apptrait.h>
#include <wx/cmdline.h>
#include "Platform/PlatformTest.h"
#ifdef TC_UNIX
#include "Platform/Unix/Process.h"
#include <sys/utsname.h>
#endif
#include "Volume/EncryptionTest.h"
#include "Application.h"
#include "FavoriteVolume.h"
#include "UserInterface.h"

namespace TrueCrypt
{
	UserInterface::UserInterface ()
	{
	}

	UserInterface::~UserInterface ()
	{
		Core->WarningEvent.Disconnect (this);
		Core->VolumeMountedEvent.Disconnect (this);
	}

	void UserInterface::CheckRequirementsForMountingVolume () const
	{
#ifdef TC_LINUX
		if (!Preferences.NonInteractive)
		{
			utsname unameData;
			if (uname (&unameData) != -1)
			{
				vector <string> osVersion = StringConverter::Split (unameData.release, ".-");
				if (osVersion.size() >= 3
					&& osVersion[0] == "2" && osVersion[1] == "6" && StringConverter::ToUInt32 (osVersion[2]) < 24)
				{
						ShowWarning (_("Your system uses an old version of the Linux kernel.\n\nDue to a bug in the Linux kernel, your system may stop responding when writing data to a TrueCrypt volume. This problem can be solved by upgrading the kernel to version 2.6.24 or later."));
				}
			}
		}
#endif // TC_LINUX
	}

	void UserInterface::CloseExplorerWindows (shared_ptr <VolumeInfo> mountedVolume) const
	{
#ifdef TC_WINDOWS
		struct Args
		{
			HWND ExplorerWindow;
			string DriveRootPath;
		};

		struct Enumerator
		{
			static BOOL CALLBACK ChildWindows (HWND hwnd, LPARAM argsLP)
			{
				Args *args = reinterpret_cast <Args *> (argsLP);
				
				char s[4096];
				SendMessageA (hwnd, WM_GETTEXT, sizeof (s), (LPARAM) s);

				if (strstr (s, args->DriveRootPath.c_str()) != NULL)
				{
					PostMessage (args->ExplorerWindow, WM_CLOSE, 0, 0);
					return FALSE;
				}

				return TRUE;
			}

			static BOOL CALLBACK TopLevelWindows (HWND hwnd, LPARAM argsLP)
			{
				Args *args = reinterpret_cast <Args *> (argsLP);

				char s[4096];
				GetClassNameA (hwnd, s, sizeof s);
				if (strcmp (s, "CabinetWClass") == 0)
				{
					GetWindowTextA (hwnd, s, sizeof s);
					if (strstr (s, args->DriveRootPath.c_str()) != NULL)
					{
						PostMessage (hwnd, WM_CLOSE, 0, 0);
						return TRUE;
					}

					args->ExplorerWindow = hwnd;
					EnumChildWindows (hwnd, ChildWindows, argsLP);
				}

				return TRUE;
			}
		};

		Args args;

		string mountPoint = mountedVolume->MountPoint;
		if (mountPoint.size() < 2 || mountPoint[1] != ':')
			return;

		args.DriveRootPath = string() + mountPoint[0] + string (":\\");
		
		EnumWindows (Enumerator::TopLevelWindows, (LPARAM) &args);
#endif
	}

	void UserInterface::DismountAllVolumes (bool ignoreOpenFiles, bool interactive) const
	{
		try
		{
			VolumeInfoList mountedVolumes = Core->GetMountedVolumes();

			if (mountedVolumes.size() < 1)
				ShowInfo (LangString["NO_VOLUMES_MOUNTED"]);

			BusyScope busy (this);
			DismountVolumes (mountedVolumes, ignoreOpenFiles, interactive);
		}
		catch (exception &e)
		{
			ShowError (e);
		}
	}

	void UserInterface::DismountVolume (shared_ptr <VolumeInfo> volume, bool ignoreOpenFiles, bool interactive) const
	{
		VolumeInfoList volumes;
		volumes.push_back (volume);

		DismountVolumes (volumes, ignoreOpenFiles, interactive);
	}

	void UserInterface::DismountVolumes (VolumeInfoList volumes, bool ignoreOpenFiles, bool interactive) const
	{
		BusyScope busy (this);

		wxString message;
		bool twoPassMode = volumes.size() > 1;
		bool volumesInUse = false;
		bool firstPass = true;

#ifdef TC_WINDOWS
		if (Preferences.CloseExplorerWindowsOnDismount)
		{
			foreach (shared_ptr <VolumeInfo> volume, volumes)
				CloseExplorerWindows (volume);
		}
#endif
		while (!volumes.empty())
		{
			VolumeInfoList volumesLeft;
			foreach (shared_ptr <VolumeInfo> volume, volumes)
			{
				try
				{
					BusyScope busy (this);
					volume = Core->DismountVolume (volume, ignoreOpenFiles);
				}
				catch (MountedVolumeInUse&)
				{
					if (!firstPass)
						throw;

					if (twoPassMode || !interactive)
					{
						volumesInUse = true;
						volumesLeft.push_back (volume);
						continue;
					}
					else
					{
						if (AskYesNo (StringFormatter (LangString["UNMOUNT_LOCK_FAILED"], wstring (volume->Path)), true, true))
						{
							BusyScope busy (this);
							volume = Core->DismountVolume (volume, true);
						}
						else
							throw UserAbort (SRC_POS);
					}
				}
				catch (...)
				{
					if (twoPassMode && firstPass)
						volumesLeft.push_back (volume);
					else
						throw;
				}

				if (volume->HiddenVolumeProtectionTriggered)
					ShowWarning (StringFormatter (LangString["DAMAGE_TO_HIDDEN_VOLUME_PREVENTED"], wstring (volume->Path)));

				if (Preferences.Verbose)
				{
					if (!message.IsEmpty())
						message += L'\n';
					message += StringFormatter (_("Volume \"{0}\" has been dismounted."), wstring (volume->Path));
				}
			}

			if (twoPassMode && firstPass)
			{
				volumes = volumesLeft;

				if (volumesInUse && interactive)
				{
					if (AskYesNo (LangString["UNMOUNTALL_LOCK_FAILED"], true, true))
						ignoreOpenFiles = true;
					else
						throw UserAbort (SRC_POS);
				}
			}
			else
				break;

			firstPass = false;
		}

		if (Preferences.Verbose && !message.IsEmpty())
			ShowInfo (message);
	}
		
	void UserInterface::DisplayVolumeProperties (const VolumeInfoList &volumes) const
	{
		if (volumes.size() < 1)
			throw_err (LangString["NO_VOLUMES_MOUNTED"]);

		wxString prop;

		foreach_ref (const VolumeInfo &volume, volumes)
		{
			prop << _("Slot") << L": " << StringConverter::FromNumber (volume.SlotNumber) << L'\n';
			prop << LangString["VOLUME"] << L": " << wstring (volume.Path) << L'\n';
#ifndef TC_WINDOWS
			prop << LangString["VIRTUAL_DEVICE"] << L": " << wstring (volume.VirtualDevice) << L'\n';
#endif
			prop << LangString["MOUNT_POINT"] << L": " << wstring (volume.MountPoint) << L'\n';
			prop << LangString["SIZE"] << L": " << SizeToString (volume.Size) << L'\n';
			prop << LangString["TYPE"] << L": " << VolumeTypeToString (volume.Type, volume.Protection) << L'\n';

			prop << LangString["READ_ONLY"] << L": " << LangString [volume.Protection == VolumeProtection::ReadOnly ? "UISTR_YES" : "UISTR_NO"] << L'\n';

			wxString protection;
			if (volume.Type == VolumeType::Hidden)
				protection = LangString["N_A_UISTR"];
			else if (volume.HiddenVolumeProtectionTriggered)
				protection = LangString["HID_VOL_DAMAGE_PREVENTED"];
			else
				protection = LangString [volume.Protection == VolumeProtection::HiddenVolumeReadOnly ? "UISTR_YES" : "UISTR_NO"];

			prop << LangString["HIDDEN_VOL_PROTECTION"] << L": " << protection << L'\n';
			prop << LangString["ENCRYPTION_ALGORITHM"] << L": " << volume.EncryptionAlgorithmName << L'\n';
			prop << LangString["KEY_SIZE"] << L": " << StringFormatter (L"{0} {1}", volume.EncryptionAlgorithmKeySize * 8, LangString ["BITS"]) << L'\n';

			if (volume.EncryptionModeName == L"XTS")
				prop << LangString["SECONDARY_KEY_SIZE_XTS"] << L": " << StringFormatter (L"{0} {1}", volume.EncryptionAlgorithmKeySize * 8, LangString ["BITS"]) << L'\n';;

			wstringstream blockSize;
			blockSize << volume.EncryptionAlgorithmBlockSize * 8;
			if (volume.EncryptionAlgorithmBlockSize != volume.EncryptionAlgorithmMinBlockSize)
				blockSize << L"/" << volume.EncryptionAlgorithmMinBlockSize * 8;

			prop << LangString["BLOCK_SIZE"] << L": " << blockSize.str() + L" " + LangString ["BITS"] << L'\n';
			prop << LangString["MODE_OF_OPERATION"] << L": " << volume.EncryptionModeName << L'\n';
			prop << LangString["PKCS5_PRF"] << L": " << volume.Pkcs5PrfName << L'\n';
	
			prop << LangString["VOLUME_FORMAT_VERSION"] << L": " << (volume.MinRequiredProgramVersion < 0x600 ? 1 : 2) << L'\n';
			prop << LangString["BACKUP_HEADER"] << L": " << LangString[volume.MinRequiredProgramVersion >= 0x600 ? "UISTR_YES" : "UISTR_NO"] << L'\n';

#ifdef TC_LINUX
			if (string (volume.VirtualDevice).find ("/dev/mapper/truecrypt") != 0)
			{
#endif
			prop << LangString["TOTAL_DATA_READ"] << L": " << SizeToString (volume.TotalDataRead) << L'\n';
			prop << LangString["TOTAL_DATA_WRITTEN"] << L": " << SizeToString (volume.TotalDataWritten) << L'\n';
#ifdef TC_LINUX
			}
#endif
		
			prop << L'\n';
		}

		ShowString (prop);
	}

	wxString UserInterface::ExceptionToMessage (const exception &ex) const
	{
		wxString message;
		
		const Exception *e = dynamic_cast <const Exception *> (&ex);
		if (e)
		{
			message = ExceptionToString (*e);

			// System exception
			const SystemException *sysEx = dynamic_cast <const SystemException *> (&ex);
			if (sysEx)
			{
				if (!message.IsEmpty())
				{
					message += L"\n\n";
				}

				message += wxString (sysEx->SystemText()).Trim (true);
			}

			if (!message.IsEmpty())
			{
				// Subject
				if (!e->GetSubject().empty())
				{
					message = message.Trim (true);

					if (message.EndsWith (L"."))
						message.Truncate (message.size() - 1);

					if (!message.EndsWith (L":"))
						message << L":\n";
					else
						message << L"\n";

					message << e->GetSubject();
				}
#ifdef DEBUG
				if (sysEx && sysEx->what())
					message << L"\n\n" << StringConverter::ToWide (sysEx->what());
#endif
				return message;
			}
		}

		// bad_alloc
		const bad_alloc *outOfMemory = dynamic_cast <const bad_alloc *> (&ex);
		if (outOfMemory)
			return _("Out of memory.");

		// Unresolved exceptions
		string typeName (StringConverter::GetTypeName (typeid (ex)));
		size_t pos = typeName.find ("TrueCrypt::");
		if (pos != string::npos)
		{
			return StringConverter::ToWide (typeName.substr (pos + string ("TrueCrypt::").size()))
				+ L" at " + StringConverter::ToWide (ex.what());
		}

		return StringConverter::ToWide (typeName) + L" at " + StringConverter::ToWide (ex.what());
	}

	wxString UserInterface::ExceptionToString (const Exception &ex) const
	{
		// Error messages
		const ErrorMessage *errMsgEx = dynamic_cast <const ErrorMessage *> (&ex);
		if (errMsgEx)
			return wstring (*errMsgEx).c_str();

		// ExecutedProcessFailed
		const ExecutedProcessFailed *execEx = dynamic_cast <const ExecutedProcessFailed *> (&ex);
		if (execEx)
		{
			wstring errOutput;

			// ElevationFailed
			if (dynamic_cast <const ElevationFailed*> (&ex))
				errOutput += wxString (_("Failed to obtain administrator privileges")) + (StringConverter::Trim (execEx->GetErrorOutput()).empty() ? L". " : L": ");

			errOutput += StringConverter::ToWide (execEx->GetErrorOutput());

			if (errOutput.empty())
				return errOutput + StringFormatter (_("Command \"{0}\" returned error {1}."), execEx->GetCommand(), execEx->GetExitCode());

			return wxString (errOutput).Trim (true);
		}

		// PasswordIncorrect 
		if (dynamic_cast <const PasswordIncorrect *> (&ex))
		{
			wxString message = ExceptionTypeToString (typeid (ex));

#ifndef TC_NO_GUI
#ifdef __WXGTK__
			if (Application::GetUserInterfaceType() != UserInterfaceType::Text)
#endif
			if (wxGetKeyState (WXK_CAPITAL))
				message += wxString (L"\n\n") + LangString["CAPSLOCK_ON"];
#endif
			return message;
		}

		// Other library exceptions
		return ExceptionTypeToString (typeid (ex));
	}

	wxString UserInterface::ExceptionTypeToString (const std::type_info &ex) const
	{
#define EX2MSG(exception, message) do { if (ex == typeid (exception)) return (message); } while (false)
		EX2MSG (DriveLetterUnavailable,				LangString["DRIVE_LETTER_UNAVAILABLE"]);
		EX2MSG (EncryptedSystemRequired,			_("This operation must be performed only when the system hosted on the volume is running."));
		EX2MSG (ExternalException,					LangString["EXCEPTION_OCCURRED"]);
		EX2MSG (InsufficientData,					_("Not enough data available."));
		EX2MSG (HigherVersionRequired,				LangString["NEW_VERSION_REQUIRED"]);
		EX2MSG (MissingArgument,					_("A required argument is missing."));
		EX2MSG (MissingVolumeData,					_("Volume data missing."));
		EX2MSG (MountPointRequired,					_("Mount point required."));
		EX2MSG (MountPointUnavailable,				_("Mount point is already in use."));
		EX2MSG (NoDriveLetterAvailable,				LangString["NO_FREE_DRIVES"]);
		EX2MSG (NoLoopbackDeviceAvailable,			_("No loopback device available."));
		EX2MSG (PasswordEmpty,						_("No password or keyfile specified."));
		EX2MSG (PasswordIncorrect,					LangString["PASSWORD_WRONG"]);
		EX2MSG (PasswordKeyfilesIncorrect,			LangString["PASSWORD_OR_KEYFILE_WRONG"]);
		EX2MSG (PasswordTooLong,					StringFormatter (_("Password is longer than {0} characters."), (int) VolumePassword::MaxSize));
		EX2MSG (ProtectionPasswordIncorrect,		_("Incorrect keyfile(s) and/or password to the protected hidden volume or the hidden volume does not exist."));
		EX2MSG (ProtectionPasswordKeyfilesIncorrect,	_("Incorrect password to the protected hidden volume or the hidden volume does not exist."));
		EX2MSG (RootDeviceUnavailable,				LangString["NODRIVER"]);
		EX2MSG (StringConversionFailed,				_("Invalid characters encountered."));
		EX2MSG (StringFormatterException,			_("Error while parsing formatted string."));
		EX2MSG (UnportablePassword,					LangString["UNSUPPORTED_CHARS_IN_PWD"]);
		EX2MSG (UnsupportedSectorSize,					LangString["LARGE_SECTOR_UNSUPPORTED"]);
		EX2MSG (VolumeAlreadyMounted,				LangString["VOL_ALREADY_MOUNTED"]);
		EX2MSG (VolumeHostInUse,					_("The host file/device is already in use."));
		EX2MSG (VolumeSlotUnavailable,				_("Volume slot unavailable."));

#ifdef TC_MACOSX
		EX2MSG (HigherFuseVersionRequired,			_("TrueCrypt requires MacFUSE 1.3 or later."));
#endif

#undef EX2MSG
		return L"";
	}

	void UserInterface::Init ()
	{
		SetAppName (Application::GetName());
		SetClassName (Application::GetName());

		LangString.Init();
		Core->Init();

		wxCmdLineParser parser;
		parser.SetCmdLine (argc, argv);
		CmdLine.reset (new CommandLineInterface (parser, InterfaceType));
		SetPreferences (CmdLine->Preferences);

		Core->SetApplicationExecutablePath (Application::GetExecutablePath());

		if (!Preferences.NonInteractive)
		{
			Core->SetAdminPasswordCallback (GetAdminPasswordRequestHandler());
		}
		else
		{
			struct AdminPasswordRequestHandler : public GetStringFunctor
			{
				virtual string operator() ()
				{
					throw ElevationFailed (SRC_POS, "sudo", 1, "");
				}
			};

			Core->SetAdminPasswordCallback (shared_ptr <GetStringFunctor> (new AdminPasswordRequestHandler));
		}

		Core->WarningEvent.Connect (EventConnector <UserInterface> (this, &UserInterface::OnWarning));
		Core->VolumeMountedEvent.Connect (EventConnector <UserInterface> (this, &UserInterface::OnVolumeMounted));
	}
	
	void UserInterface::ListMountedVolumes (const VolumeInfoList &volumes) const
	{
		if (volumes.size() < 1)
			throw_err (LangString["NO_VOLUMES_MOUNTED"]);

		wxString message;

		foreach_ref (const VolumeInfo &volume, volumes)
		{
			message << volume.SlotNumber << L": " << StringConverter::QuoteSpaces (volume.Path);

			if (!volume.VirtualDevice.IsEmpty())
				message << L' ' << wstring (volume.VirtualDevice);
			else
				message << L" - ";

			if (!volume.MountPoint.IsEmpty())
				message << L' ' << StringConverter::QuoteSpaces (volume.MountPoint);
			else
				message << L" - ";

			message << L'\n';
		}

		ShowString (message);
	}

	VolumeInfoList UserInterface::MountAllDeviceHostedVolumes (MountOptions &options) const
	{
		BusyScope busy (this);

		VolumeInfoList newMountedVolumes;

		if (!options.MountPoint)
			options.MountPoint.reset (new DirectoryPath);

		Core->CoalesceSlotNumberAndMountPoint (options);

		bool sharedAccessAllowed = options.SharedAccessAllowed;
		bool someVolumesShared = false;

		HostDeviceList devices;
		foreach (shared_ptr <HostDevice> device, Core->GetHostDevices (true))
		{
			devices.push_back (device);

			foreach (shared_ptr <HostDevice> partition, device->Partitions)
				devices.push_back (partition);
		}

		set <wstring> mountedVolumes;
		foreach_ref (const VolumeInfo &v, Core->GetMountedVolumes())
			mountedVolumes.insert (v.Path);

		bool protectedVolumeMounted = false;
		bool legacyVolumeMounted = false;

		foreach_ref (const HostDevice &device, devices)
		{
			if (mountedVolumes.find (wstring (device.Path)) != mountedVolumes.end())
				continue;

			Yield();
			options.SlotNumber = Core->GetFirstFreeSlotNumber (options.SlotNumber);
			options.MountPoint.reset (new DirectoryPath);
			options.Path.reset (new VolumePath (device.Path));

			try
			{
				try
				{
					options.SharedAccessAllowed = sharedAccessAllowed;
					newMountedVolumes.push_back (Core->MountVolume (options));
				}
				catch (VolumeHostInUse&)
				{
					if (!sharedAccessAllowed)
					{
						try
						{
							options.SharedAccessAllowed = true;
							newMountedVolumes.push_back (Core->MountVolume (options));
							someVolumesShared = true;
						}
						catch (VolumeHostInUse&)
						{
							continue;
						}
					}
					else
						continue;
				}

				if (newMountedVolumes.back()->Protection == VolumeProtection::HiddenVolumeReadOnly)
					protectedVolumeMounted = true;

				if (newMountedVolumes.back()->EncryptionAlgorithmMinBlockSize == 8)
					legacyVolumeMounted = true;
			}
			catch (DriverError&) { }
			catch (MissingVolumeData&) { }
			catch (PasswordException&) { }
			catch (SystemException&) { }
		}

		if (newMountedVolumes.empty())
		{
			ShowWarning (LangString [options.Keyfiles && !options.Keyfiles->empty() ? "PASSWORD_OR_KEYFILE_WRONG_AUTOMOUNT" : "PASSWORD_WRONG_AUTOMOUNT"]);
		}
		else
		{
			if (someVolumesShared)
				ShowWarning ("DEVICE_IN_USE_INFO");

			if (legacyVolumeMounted)
				ShowWarning ("WARN_64_BIT_BLOCK_CIPHER");

			if (protectedVolumeMounted)
				ShowInfo (LangString[newMountedVolumes.size() > 1 ? "HIDVOL_PROT_WARN_AFTER_MOUNT_PLURAL" : "HIDVOL_PROT_WARN_AFTER_MOUNT"]);
		}

		return newMountedVolumes;
	}

	VolumeInfoList UserInterface::MountAllFavoriteVolumes (MountOptions &options) const
	{
		BusyScope busy (this);
		
		VolumeInfoList newMountedVolumes;
		foreach_ref (const FavoriteVolume &favorite, FavoriteVolume::LoadList())
		{
			shared_ptr <VolumeInfo> mountedVolume = Core->GetMountedVolume (favorite.Path);
			if (mountedVolume)
			{
				if (mountedVolume->MountPoint != favorite.MountPoint)
					ShowInfo (StringFormatter (LangString["VOLUME_ALREADY_MOUNTED"], wstring (favorite.Path)));
				continue;
			}

			favorite.ToMountOptions (options);

			if (Preferences.NonInteractive)
			{
				BusyScope busy (this);
				newMountedVolumes.push_back (Core->MountVolume (options));
			}
			else
			{
				try
				{
					BusyScope busy (this);
					newMountedVolumes.push_back (Core->MountVolume (options));
				}
				catch (...)
				{
					shared_ptr <VolumeInfo> volume = MountVolume (options);
					if (!volume)
						break;
					newMountedVolumes.push_back (volume);
				}
			}
		}

		return newMountedVolumes;
	}

	shared_ptr <VolumeInfo> UserInterface::MountVolume (MountOptions &options) const
	{
		shared_ptr <VolumeInfo> volume;

		try
		{
			volume = Core->MountVolume (options);
		}
		catch (VolumeHostInUse&)
		{
			if (options.SharedAccessAllowed)
				throw_err (LangString["FILE_IN_USE_FAILED"]);

			if (!AskYesNo (StringFormatter (LangString["VOLUME_HOST_IN_USE"], wstring (*options.Path)), false, true))
				throw UserAbort (SRC_POS);

			try
			{
				options.SharedAccessAllowed = true;
				volume = Core->MountVolume (options);
			}
			catch (VolumeHostInUse&)
			{
				throw_err (LangString["FILE_IN_USE_FAILED"]);
			}
		}

		if (volume->EncryptionAlgorithmMinBlockSize == 8)
			ShowWarning ("WARN_64_BIT_BLOCK_CIPHER");

		if (VolumeHasUnrecommendedExtension (*options.Path))
			ShowWarning ("EXE_FILE_EXTENSION_MOUNT_WARNING");

		if (options.Protection == VolumeProtection::HiddenVolumeReadOnly)
			ShowInfo ("HIDVOL_PROT_WARN_AFTER_MOUNT");

		return volume;
	}

	void UserInterface::OnUnhandledException ()
	{
		try
		{
			throw;
		}
		catch (UserAbort&)
		{
		}
		catch (exception &e)
		{
			ShowError (e);
		}
		catch (...)
		{
			ShowError (_("Unknown exception occurred."));
		}

		Yield();
		Application::SetExitCode (1);
	}

	void UserInterface::OnVolumeMounted (EventArgs &args)
	{
		shared_ptr <VolumeInfo> mountedVolume = (dynamic_cast <VolumeEventArgs &> (args)).mVolume;

		if (Preferences.OpenExplorerWindowAfterMount && !mountedVolume->MountPoint.IsEmpty())
			OpenExplorerWindow (mountedVolume->MountPoint);
	}
	
	void UserInterface::OnWarning (EventArgs &args)
	{
		ExceptionEventArgs &e = dynamic_cast <ExceptionEventArgs &> (args);
		ShowWarning (e.mException);
	}

	void UserInterface::OpenExplorerWindow (const DirectoryPath &path)
	{
		if (path.IsEmpty())
			return;

		list <string> args;

#ifdef TC_WINDOWS

		wstring p (Directory::AppendSeparator (path));
		SHFILEINFO fInfo;
		SHGetFileInfo (p.c_str(), 0, &fInfo, sizeof (fInfo), 0); // Force explorer to discover the drive
		ShellExecute (GetTopWindow() ? static_cast <HWND> (GetTopWindow()->GetHandle()) : nullptr, L"open", p.c_str(), nullptr, nullptr, SW_SHOWNORMAL);

#elif defined (TC_MACOSX)

		args.push_back (string (path));
		Process::Execute ("open", args);

#else
		// MIME handler for directory seems to be unavailable through wxWidgets
		if (GetTraits()->GetDesktopEnvironment() == L"GNOME")
		{
			args.push_back ("--no-default-window");
			args.push_back ("--no-desktop");
			args.push_back (string (path));
			try
			{
				Process::Execute ("nautilus", args, 2000);
			}
			catch (TimeOut&) { }
		}
		else if (GetTraits()->GetDesktopEnvironment() == L"KDE")
		{
			args.push_back ("openURL");
			args.push_back (string (path));
			try
			{
				Process::Execute ("kfmclient", args, 2000);
			}
			catch (TimeOut&) { }
		}
#endif
	}

	bool UserInterface::ProcessCommandLine ()
	{
		CommandLineInterface &cmdLine = *CmdLine;

		switch (cmdLine.ArgCommand)
		{
		case CommandId::None:
			return false;

		case CommandId::AutoMountDevices:
		case CommandId::AutoMountFavorites:
		case CommandId::AutoMountDevicesFavorites:
		case CommandId::MountVolume:
			{
				cmdLine.ArgMountOptions.Path = cmdLine.ArgVolumePath;
				cmdLine.ArgMountOptions.MountPoint = cmdLine.ArgMountPoint;
				cmdLine.ArgMountOptions.Password = cmdLine.ArgPassword;
				cmdLine.ArgMountOptions.Keyfiles = cmdLine.ArgKeyfiles;
				cmdLine.ArgMountOptions.SharedAccessAllowed = cmdLine.ArgForce;

				VolumeInfoList mountedVolumes;
				switch (cmdLine.ArgCommand)
				{
				case CommandId::AutoMountDevices:
				case CommandId::AutoMountFavorites:
				case CommandId::AutoMountDevicesFavorites:
					{
						if (cmdLine.ArgCommand == CommandId::AutoMountDevices || cmdLine.ArgCommand == CommandId::AutoMountDevicesFavorites)
						{
							if (Preferences.NonInteractive)
								mountedVolumes = UserInterface::MountAllDeviceHostedVolumes (cmdLine.ArgMountOptions);
							else
								mountedVolumes = MountAllDeviceHostedVolumes (cmdLine.ArgMountOptions);
						}

						if (cmdLine.ArgCommand == CommandId::AutoMountFavorites || cmdLine.ArgCommand == CommandId::AutoMountDevicesFavorites)
						{
							foreach (shared_ptr <VolumeInfo> v, MountAllFavoriteVolumes(cmdLine.ArgMountOptions))
								mountedVolumes.push_back (v);
						}
					}
					break;


					break;

				case CommandId::MountVolume:
					if (Preferences.OpenExplorerWindowAfterMount)
					{
						// Open explorer window for an already mounted volume
						shared_ptr <VolumeInfo> mountedVolume = Core->GetMountedVolume (*cmdLine.ArgMountOptions.Path);
						if (mountedVolume && !mountedVolume->MountPoint.IsEmpty())
						{
							OpenExplorerWindow (mountedVolume->MountPoint);
							break;
						}
					}

					if (Preferences.NonInteractive)
					{
						// Volume path
						if (!cmdLine.ArgMountOptions.Path)
							throw MissingArgument (SRC_POS);

						mountedVolumes.push_back (Core->MountVolume (cmdLine.ArgMountOptions));
					}
					else
					{
						shared_ptr <VolumeInfo> volume = MountVolume (cmdLine.ArgMountOptions);
						if (!volume)
						{
							Application::SetExitCode (1);
							throw UserAbort (SRC_POS);
						}
						mountedVolumes.push_back (volume);
					}
					break;

				default:
					throw ParameterIncorrect (SRC_POS);
				}

				if (Preferences.Verbose && !mountedVolumes.empty())
				{
					wxString message;
					foreach_ref (const VolumeInfo &volume, mountedVolumes)
					{
						if (!message.IsEmpty())
							message += L'\n';
						message += StringFormatter (_("Volume \"{0}\" has been mounted."), wstring (volume.Path));
					}
					ShowInfo (message);
				}
			}
			return true;

		case CommandId::ChangePassword:
			ChangePassword (cmdLine.ArgVolumePath, cmdLine.ArgPassword, cmdLine.ArgKeyfiles, cmdLine.ArgNewPassword, cmdLine.ArgNewKeyfiles, cmdLine.ArgHash);
			return true;

		case CommandId::CreateVolume:
			{
				make_shared_auto (VolumeCreationOptions, options);

				if (cmdLine.ArgHash)
				{
					options->VolumeHeaderKdf = Pkcs5Kdf::GetAlgorithm (*cmdLine.ArgHash);
					RandomNumberGenerator::SetHash (cmdLine.ArgHash);
				}
				
				options->EA = cmdLine.ArgEncryptionAlgorithm;
				options->Filesystem = cmdLine.ArgFilesystem;
				options->Keyfiles = cmdLine.ArgKeyfiles;
				options->Password = cmdLine.ArgPassword;
				options->Quick = cmdLine.ArgQuick;
				options->Size = (cmdLine.ArgSize + SECTOR_SIZE - 1) & ~(SECTOR_SIZE - 1);
				options->Type = cmdLine.ArgVolumeType;

				if (cmdLine.ArgVolumePath)
					options->Path = VolumePath (*cmdLine.ArgVolumePath);

				CreateVolume (options, cmdLine.ArgRandomSourcePath);
				return true;
			}

		case CommandId::DismountVolumes:
			DismountVolumes (cmdLine.ArgVolumes, cmdLine.ArgForce, !Preferences.NonInteractive);
			return true;

		case CommandId::DisplayVersion:
			ShowString (Application::GetName() + L" " + StringConverter::ToWide (Version::String()) + L"\n");
			return true;

		case CommandId::DisplayVolumeProperties:
			DisplayVolumeProperties (cmdLine.ArgVolumes);
			return true;

		case CommandId::Help:
			{
				wstring helpText = StringConverter::ToWide (
					"Synopsis:\n"
					"\n"
					"truecrypt [OPTIONS] COMMAND\n"
					"truecrypt [OPTIONS] VOLUME_PATH [MOUNT_DIRECTORY]\n"
					"\n"
					"\n"
					"Commands:\n"
					"\n"
					"--auto-mount=devices|favorites\n"
					" Auto mount device-hosted or favorite volumes.\n"
					"\n"
					"-c, --create[=VOLUME_PATH]\n"
					" Create a new volume. Most options are requested from the user if not specified\n"
					" on command line. See also options --encryption, -k, --filesystem, --hash, -p,\n"
					" --random-source, --quick, --size, --volume-type. Note that passing some of the\n"
					" options may affect security of the volume (see option -p for more information).\n"
					"\n"
					" Inexperienced users should use the graphical user interface to create a hidden\n"
					" volume. When using the text user interface, the following procedure must be\n"
					" followed to create a hidden volume:\n"
					"  1) Create an outer volume with no filesystem.\n"
					"  2) Create a hidden volume within the outer volume.\n"
					"  3) Mount the outer volume using hidden volume protection.\n"
					"  4) Create a filesystem on the virtual device of the outer volume.\n"
					"  5) Mount the new filesystem and fill it with data.\n"
					"  6) Dismount the outer volume.\n"
					"  If at any step the hidden volume protection is triggered, start again from 1).\n"
					"\n"
					"-C, --change[=VOLUME_PATH]\n"
					" Change a password and/or keyfile(s) of a volume. Most options are requested\n"
					" from the user if not specified on command line. PKCS-5 PRF HMAC hash\n"
					" algorithm can be changed with option --hash. See also options -k,\n"
					" --new-keyfiles, --new-password, -p, --random-source, -v.\n"
					"\n"
					"-d, --dismount[=MOUNTED_VOLUME]\n"
					" Dismount a mounted volume. If MOUNTED_VOLUME is not specified, all\n"
					" volumes are dismounted. See below for description of MOUNTED_VOLUME.\n"
					"\n"
					"-l, --list[=MOUNTED_VOLUME]\n"
					" Display a list of mounted volumes. If MOUNTED_VOLUME is not specified, all\n"
					" volumes are listed. By default, the list contains only volume path, virtual\n"
					" device, and mount point. A more detailed list can be enabled by verbose\n"
					" output option (-v). See below for description of MOUNTED_VOLUME.\n"
					"\n"
					"--mount[=VOLUME_PATH]\n"
					" Mount a volume. Volume path and other options are requested from the user\n"
					" if not specified on command line.\n"
					"\n"
					"--test\n"
					" Test internal algorithms used in the process of encryption and decryption.\n"
					"\n"
					"--version\n"
					" Display program version.\n"
					"\n"
					"--volume-properties[=MOUNTED_VOLUME]\n"
					" Display properties of a mounted volume. See below for description of\n"
					" MOUNTED_VOLUME.\n"
					"\n"
					"MOUNTED_VOLUME:\n"
					" Specifies a mounted volume. One of the following forms can be used:\n"
					" 1) Path to the encrypted TrueCrypt volume.\n"
					" 2) Mount directory of the volume's filesystem (if mounted).\n"
					" 3) Slot number of the mounted volume (requires --slot).\n"
					"\n"
					"\n"
					"Options:\n"
					"\n"
					"--encryption=ENCRYPTION_ALGORITHM\n"
					" Use specified encryption algorithm when creating a new volume.\n"
					"\n"
					"--filesystem=TYPE\n"
					" Filesystem type to mount. The TYPE argument is passed to mount(8) command\n"
					" with option -t. Default type is 'auto'. When creating a new volume, this\n"
					" option specifies the filesystem to be created on the new volume.\n"
					" Filesystem type 'none' disables mounting or creating a filesystem.\n"
					"\n"
					"--force\n"
					" Force mounting of a volume in use, dismounting of a volume in use, or\n"
					" overwriting a file. Note that this option has no effect on some platforms.\n"
					"\n"
					"--fs-options=OPTIONS\n"
					" Filesystem mount options. The OPTIONS argument is passed to mount(8)\n"
					" command with option -o when a filesystem on a TrueCrypt volume is mounted.\n"
					" This option is not available on some platforms.\n"
					"\n"
					"--hash=HASH\n"
					" Use specified hash algorithm when creating a new volume or changing password\n"
					" and/or keyfiles.\n"
					"\n"
					"-k, --keyfiles=KEYFILE1,KEYFILE2,KEYFILE3,..\n"
					" Use specified keyfiles when mounting a volume or when changing password\n"
					" and/or keyfiles. When a directory is specified, all files inside it will be\n"
					" used (non-recursively). Multiple keyfiles must be separated by comma.\n"
					" Use double comma (,,) to specify a comma contained in keyfile's name.\n"
					" An empty keyfile (-k \"\") disables interactive requests for keyfiles. See also\n"
					" options --new-keyfiles, --protection-keyfiles.\n"
					"\n"
					"-m, --mount-options=headerbak|nokernelcrypto|readonly|ro|timestamp|ts\n"
					" Specify comma-separated mount options for a TrueCrypt volume:\n"
					"  headerbak: Use backup headers when mounting a volume.\n"
					"  nokernelcrypto: Do not use kernel cryptographic services.\n"
					"  readonly|ro: Mount volume read-only.\n"
					"  timestamp|ts: Update (do not preserve) host-file timestamps.\n"
					" See also option --fs-options.\n"
					"\n"
					"-p, --password=PASSWORD\n"
					" Use specified password to mount/open a volume. An empty password can also be\n"
					" specified (-p \"\"). Note that passing a password on the command line is\n"
					" potentially insecure as the password may be visible in the process list\n"
					" (see ps(1)) and/or stored in a command history file or system logs.\n"
					"\n"
					"--protect-hidden=yes|no\n"
					" Write-protect a hidden volume when mounting an outer volume. Before mounting\n"
					" the outer volume, the user will be prompted for a password to open the hidden\n"
					" volume. The size and position of the hidden volume is then determined and the\n"
					" outer volume is mounted with all sectors belonging to the hidden volume\n"
					" protected against write operations. When a write to the protected area is\n"
					" prevented, the whole volume is switched to read-only mode. Verbose list\n"
					" (-v -l) can be used to query the state of the hidden volume protection.\n"
					" Warning message is displayed when a volume switched to read-only is being\n"
					" dismounted.\n"
					"\n"
					"--protection-keyfiles=KEYFILE1,KEYFILE2,KEYFILE3,..\n"
					" Use specified keyfiles to open a hidden volume to be protected. This option\n"
					" may be used only when mounting an outer volume with hidden volume protected.\n"
					" See also options -k and --protect-hidden.\n"
					"\n"
					"--protection-password=PASSWORD\n"
					" Use specified password to open a hidden volume to be protected. This option\n"
					" may be used only when mounting an outer volume with hidden volume protected.\n"
					" See also options -p and --protect-hidden.\n"
					"\n"
					"--quick\n"
					" Use quick format when creating a new volume. This option can be used only\n"
					" when creating a device-hosted volume and must not be used when creating an\n"
					" outer volume.\n"
					"\n"
					"--random-source=FILE\n"
					" Use FILE as a source of random data (e.g., when creating a volume).\n"
					"\n"
					"--slot=SLOT\n"
					" Use specified slot number when mounting, dismounting, or listing a volume.\n"
					"\n"
					"--size=SIZE\n"
					" Use specified size in bytes when creating a new volume.\n"
					"\n"
					"-t, --text\n"
					" Use text user interface. Graphical user interface is used by default if\n"
					" available.\n"
					"\n"
					"--volume-type=TYPE\n"
					" Use specified volume type when creating a new volume. TYPE can be 'normal'\n"
					" or 'hidden'. See option -c for more information on creating hidden volumes.\n"
					"\n"
					"-v, --verbose\n"
					" Enable verbose output.\n"
					"\n"
					"\nExamples:\n\n"
					"Create a new volume using text interface:\n"
					"truecrypt -t -c\n"
					"\n"
					"Mount a volume:\n"
					"truecrypt volume.tc /media/truecrypt1\n"
					"\n"
					"Mount a volume read-only, using keyfiles:\n"
					"truecrypt -m ro -k keyfile1,keyfile2 volume.tc\n"
					"\n"
					"Mount a volume without mounting its filesystem:\n"
					"truecrypt --filesystem=none volume.tc\n"
					"\n"
					"Mount a volume prompting only for its password:\n"
					"truecrypt -t -k \"\" --protect-hidden=no volume.tc /media/truecrypt1\n"
					"\n"
					"Dismount a volume:\n"
					"truecrypt -d volume.tc\n"
					"\n"
					"Dismount all mounted volumes:\n"
					"truecrypt -d\n"
				);

#ifndef TC_NO_GUI
				if (Application::GetUserInterfaceType() == UserInterfaceType::Graphic)
				{
					wxDialog dialog (nullptr, wxID_ANY, _("TrueCrypt Command Line Help"), wxDefaultPosition, wxSize (600,400));

					wxTextCtrl *textCtrl = new wxTextCtrl (&dialog, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);
					textCtrl->SetValue (helpText);

					wxBoxSizer *sizer = new wxBoxSizer (wxVERTICAL);
					sizer->Add (textCtrl, 1, wxALL | wxEXPAND, 5);
					sizer->Add (new wxButton (&dialog, wxID_OK, _("OK")), 0, wxALL | wxALIGN_CENTER_HORIZONTAL, 5);

					dialog.SetSizer (sizer);
					dialog.Layout();
					dialog.ShowModal();
				}
				else
#endif // !TC_NO_GUI
				{
					ShowString (L"\n\n");
					ShowString (helpText);
				}
			}
			return true;

		case CommandId::ListVolumes:
			if (Preferences.Verbose)
				DisplayVolumeProperties (cmdLine.ArgVolumes);
			else
				ListMountedVolumes (cmdLine.ArgVolumes);
			return true;

		case CommandId::Test:
			Test();
			return true;

		default:
			throw ParameterIncorrect (SRC_POS);
		}

		return false;
	}

	void UserInterface::SetPreferences (const UserPreferences &preferences)
	{
		Preferences = preferences;
		PreferencesUpdatedEvent.Raise();
	}

	void UserInterface::ShowError (const exception &ex) const
	{
		if (!dynamic_cast <const UserAbort*> (&ex))
			DoShowError (ExceptionToMessage (ex));
	}

	wxString UserInterface::SizeToString (uint64 size) const
	{
		wstringstream s;
		if (size > 1024ULL*1024*1024*1024*1024*99)
			s << size/1024/1024/1024/1024/1024 << L" " << LangString["PB"].c_str();
		else if (size > 1024ULL*1024*1024*1024*1024)
			return wxString::Format (L"%.1f %s", (double)(size/1024.0/1024/1024/1024/1024), LangString["PB"].c_str());
		else if (size > 1024ULL*1024*1024*1024*99)
			s << size/1024/1024/1024/1024 << L" " << LangString["TB"].c_str();
		else if (size > 1024ULL*1024*1024*1024)
			return wxString::Format (L"%.1f %s", (double)(size/1024.0/1024/1024/1024), LangString["TB"].c_str());
		else if (size > 1024ULL*1024*1024*99)
			s << size/1024/1024/1024 << L" " << LangString["GB"].c_str();
		else if (size > 1024ULL*1024*1024)
			return wxString::Format (L"%.1f %s", (double)(size/1024.0/1024/1024), LangString["GB"].c_str());
		else if (size > 1024ULL*1024*99)
			s << size/1024/1024 << L" " << LangString["MB"].c_str();
		else if (size > 1024ULL*1024)
			return wxString::Format (L"%.1f %s", (double)(size/1024.0/1024), LangString["MB"].c_str());
		else if (size > 1024ULL)
			s << size/1024 << L" " << LangString["KB"].c_str();
		else
			s << size << L" " << LangString["BYTE"].c_str();

		return s.str();
	}

	wxString UserInterface::SpeedToString (uint64 speed) const
	{
		wstringstream s;

		if (speed > 1024ULL*1024*1024*1024*1024*99)
			s << speed/1024/1024/1024/1024/1024 << L" " << LangString["PB_PER_SEC"].c_str();
		else if (speed > 1024ULL*1024*1024*1024*1024)
			return wxString::Format (L"%.1f %s", (double)(speed/1024.0/1024/1024/1024/1024), LangString["PB_PER_SEC"].c_str());
		else if (speed > 1024ULL*1024*1024*1024*99)
			s << speed/1024/1024/1024/1024 << L" " << LangString["TB_PER_SEC"].c_str();
		else if (speed > 1024ULL*1024*1024*1024)
			return wxString::Format (L"%.1f %s", (double)(speed/1024.0/1024/1024/1024), LangString["TB_PER_SEC"].c_str());
		else if (speed > 1024ULL*1024*1024*99)
			s << speed/1024/1024/1024 << L" " << LangString["GB_PER_SEC"].c_str();
		else if (speed > 1024ULL*1024*1024)
			return wxString::Format (L"%.1f %s", (double)(speed/1024.0/1024/1024), LangString["GB_PER_SEC"].c_str());
		else if (speed > 1024ULL*1024*99)
			s << speed/1024/1024 << L" " << LangString["MB_PER_SEC"].c_str();
		else if (speed > 1024ULL*1024)
			return wxString::Format (L"%.1f %s", (double)(speed/1024.0/1024), LangString["MB_PER_SEC"].c_str());
		else if (speed > 1024ULL)
			s << speed/1024 << L" " << LangString["KB_PER_SEC"].c_str();
		else
			s << speed << L" " << LangString["B_PER_SEC"].c_str();

		return s.str();
	}

	void UserInterface::Test () const
	{
		if (!PlatformTest::TestAll())
			throw TestFailed (SRC_POS);

		EncryptionTest::TestAll();

		// StringFormatter
		if (StringFormatter (L"{9} {8} {7} {6} {5} {4} {3} {2} {1} {0} {{0}}", "1", L"2", '3', L'4', 5, 6, 7, 8, 9, 10) != L"10 9 8 7 6 5 4 3 2 1 {0}")
			throw TestFailed (SRC_POS);
		try
		{
			StringFormatter (L"{0} {1}", 1);
			throw TestFailed (SRC_POS);
		}
		catch (StringFormatterException&) { }

		try
		{
			StringFormatter (L"{0} {1} {1}", 1, 2, 3);
			throw TestFailed (SRC_POS);
		}
		catch (StringFormatterException&) { }

		try
		{
			StringFormatter (L"{0} 1}", 1, 2);
			throw TestFailed (SRC_POS);
		}
		catch (StringFormatterException&) { }

		try
		{
			StringFormatter (L"{0} {1", 1, 2);
			throw TestFailed (SRC_POS);
		}
		catch (StringFormatterException&) { }

		ShowInfo ("TESTS_PASSED");
	}

	wxString UserInterface::TimeSpanToString (uint64 seconds) const
	{
		wstringstream s;

		if (seconds >= 60 * 60 * 24 * 2)
			s << seconds / (60 * 24 * 60) << L" " << LangString["DAYS"].c_str();
		else if (seconds >= 120 * 60)
			s << seconds / (60 * 60) << L" " << LangString["HOURS"].c_str();
		else if (seconds >= 120)
			s << seconds / 60 << L" " << LangString["MINUTES"].c_str();
		else
			s << seconds << L" " << LangString["SECONDS"].c_str();

		return s.str();
	}
	
	bool UserInterface::VolumeHasUnrecommendedExtension (const VolumePath &path) const
	{
		wxString ext = wxFileName (wxString (wstring (path)).Lower()).GetExt();
		return ext.IsSameAs (L"exe") || ext.IsSameAs (L"sys") || ext.IsSameAs (L"dll");
	}

	wxString UserInterface::VolumeTimeToString (VolumeTime volumeTime) const
	{
		wxString dateStr = VolumeTimeToDateTime (volumeTime).Format();

#ifdef TC_WINDOWS

		FILETIME ft;
		*(unsigned __int64 *)(&ft) = volumeTime;
		SYSTEMTIME st;
		FileTimeToSystemTime (&ft, &st);

		wchar_t wstr[1024];
		if (GetDateFormat (LOCALE_USER_DEFAULT, 0, &st, 0, wstr, array_capacity (wstr)) != 0)
		{
			dateStr = wstr;
			GetTimeFormat (LOCALE_USER_DEFAULT, 0, &st, 0, wstr, array_capacity (wstr));
			dateStr += wxString (L" ") + wstr;
		}
#endif
		return dateStr;
	}

	wxString UserInterface::VolumeTypeToString (VolumeType::Enum type, VolumeProtection::Enum protection) const
	{
		switch (type)
		{
		case VolumeType::Normal:
			return LangString[protection == VolumeProtection::HiddenVolumeReadOnly ? "OUTER" : "NORMAL"];

		case VolumeType::Hidden:
			return LangString["HIDDEN"];

		default:
			return L"?";
		}
	}
}
