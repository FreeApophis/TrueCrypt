/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "System.h"
#ifdef TC_UNIX
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#endif

#include "Application.h"
#include "TextUserInterface.h"

namespace TrueCrypt
{
	TextUserInterface::TextUserInterface ()
	{
#ifdef TC_UNIX
		signal (SIGHUP, OnSignal);
		signal (SIGINT, OnSignal);
		signal (SIGQUIT, OnSignal);
		signal (SIGTERM, OnSignal);
#endif

		FInputStream.reset (new wxFFileInputStream (stdin));
		TextInputStream.reset (new wxTextInputStream (*FInputStream));
	}

	TextUserInterface::~TextUserInterface ()
	{
#ifdef TC_UNIX
		signal (SIGHUP, SIG_DFL);
		signal (SIGINT, SIG_DFL);
		signal (SIGQUIT, SIG_DFL);
		signal (SIGTERM, SIG_DFL);
#endif
	}

	shared_ptr <KeyfileList> TextUserInterface::AskKeyfiles (const wxString &message) const
	{
		wxString msg = _("Enter keyfile");
		if (!message.empty())
			msg = message;

		make_shared_auto (KeyfileList, keyfiles);

		wxString s;
		wxString m = msg + L" [" + _("none") + L"]: ";
		while (!(s = AskString (m)).empty())
		{
			keyfiles->push_back (make_shared <Keyfile> (wstring (s)));
			m = msg + L" [" + _("finish") + L"]: ";
		}

		return keyfiles;
	}

	shared_ptr <VolumePassword> TextUserInterface::AskPassword (const wxString &message, bool verify) const
	{
		wxString msg = LangString["ENTER_PASSWORD"] + L": ";
		if (!message.empty())
			msg = message + L": ";

		SetTerminalEcho (false);
		finally_do ({ TextUserInterface::SetTerminalEcho (true); });

		wchar_t passwordBuf[4096];
		finally_do_arg (BufferPtr, BufferPtr (reinterpret_cast <byte *> (passwordBuf), sizeof (passwordBuf)), { finally_arg.Erase(); });

		make_shared_auto (VolumePassword, password);

		bool verPhase = false;
		while (true)
		{
			ShowString (verPhase ? wxString (_("Re-enter password: ")) : msg);

			const wxString &passwordStr = TextInputStream->ReadLine();
			CheckInputStream();

			size_t length = passwordStr.size();

			ShowString (L"\n");

			if (length < 1)
			{
				throw_sys_if (ferror (stdin));

				password->Set (passwordBuf, 0);
				return password;
			}

			for (size_t i = 0; i < length && i < VolumePassword::MaxSize; ++i)
			{
				passwordBuf[i] = (wchar_t) passwordStr[i];
				const_cast <wchar_t *> (passwordStr.c_str())[i] = L'X';
			}

			if (verify && verPhase)
			{
				make_shared_auto (VolumePassword, verPassword);
				verPassword->Set (passwordBuf, length);

				if (*password != *verPassword)
				{
					ShowInfo (_("Passwords do not match."));
					ShowString (L"\n");
					verPhase = false;
					continue;
				}
			}

			password->Set (passwordBuf, length);

			if (!verPhase)
			{
				try
				{
					password->CheckPortability();
				}
				catch (UnportablePassword &e)
				{
					if (verify)
					{
						ShowError (e);
						verPhase = false;
						continue;
					}

					ShowWarning ("UNSUPPORTED_CHARS_IN_PWD_RECOM");
				}

				if (verify)
				{
					if (password->Size() < VolumePassword::WarningSizeThreshold)
					{
						SetTerminalEcho (true);
						finally_do ({ TextUserInterface::SetTerminalEcho (false); });

						if (!AskYesNo (LangString ["PASSWORD_LENGTH_WARNING"], false, true))
						{
							ShowString (L"\n");
							continue;
						}
						ShowString (L"\n");
					}
				}
			}

			if (!verify || verPhase)
				return password;

			if (!verPhase)
				verPhase = true;
		}

		return password;
	}
	
	size_t TextUserInterface::AskSelection (size_t optionCount, size_t defaultOption) const
	{
		while (true)
		{
			wstring selectionStr = AskString (StringFormatter (_("Select [{0}]: "), (uint32) defaultOption));
			size_t selection;

			if (selectionStr.empty() && defaultOption != -1)
				return defaultOption;

			try
			{
				selection = StringConverter::ToUInt32 (selectionStr);
			}
			catch (...)
			{
				continue;
			}

			if (selection > 0 && selection <= optionCount)
				return selection;
		}
	}

	wstring TextUserInterface::AskString (const wxString &message) const
	{
		ShowString (message);

		wstring str (TextInputStream->ReadLine());
		CheckInputStream();

		return str;
	}
	
	bool TextUserInterface::AskYesNo (const wxString &message, bool defaultYes, bool warning) const
	{
		while (true)
		{
			wxString s = AskString (StringFormatter (L"{0} (y={1}/n={2}) [{3}]: ",
				message, LangString["YES"], LangString["NO"], LangString[defaultYes ? "YES" : "NO"]));

			if (s.IsSameAs (L'n', false) || s.IsSameAs (L"no", false) || !defaultYes && s.empty())
				return false;

			if (s.IsSameAs (L'y', false) || s.IsSameAs (L"yes", false) || defaultYes && s.empty())
				return true;
		};
	}

	shared_ptr <VolumePath> TextUserInterface::AskVolumePath (const wxString &message) const
	{
		return make_shared <VolumePath> (AskString (message.empty() ? wxString (_("Enter volume path: ")) : message));
	}

	void TextUserInterface::ChangePassword (shared_ptr <VolumePath> volumePath, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, shared_ptr <VolumePassword> newPassword, shared_ptr <KeyfileList> newKeyfiles, shared_ptr <Hash> newHash) const
	{
		shared_ptr <Volume> volume;

		// Volume path
		if (!volumePath.get())
		{
			if (Preferences.NonInteractive)
				throw MissingArgument (SRC_POS);

			volumePath = AskVolumePath ();
		}

		bool passwordInteractive = !password.get();
		bool keyfilesInteractive = !keyfiles.get();

		while (true)
		{
			// Current password
			if (!passwordInteractive)
			{
				try
				{
					password->CheckPortability();
				}
				catch (UnportablePassword &)
				{
					ShowWarning ("UNSUPPORTED_CHARS_IN_PWD_RECOM");
				}
			}
			else if (!Preferences.NonInteractive)
			{
				password = AskPassword ();
			}

			// Current keyfiles
			try
			{
				if (keyfilesInteractive)
				{
					// Ask for keyfiles only if required
					try
					{
						keyfiles.reset (new KeyfileList);
						volume = Core->OpenVolume (volumePath, Preferences.DefaultMountOptions.PreserveTimestamps, password, keyfiles);
					}
					catch (PasswordException&)
					{
						if (!Preferences.NonInteractive)
							keyfiles = AskKeyfiles ();
					}
				}	

				if (!volume.get())
					volume = Core->OpenVolume (volumePath, Preferences.DefaultMountOptions.PreserveTimestamps, password, keyfiles);
			}
			catch (PasswordException &e)
			{
				if (Preferences.NonInteractive || !passwordInteractive || !keyfilesInteractive)
					throw;

				ShowInfo (e);
				continue;
			}

			break;
		}

		// New password
		if (newPassword.get())
			newPassword->CheckPortability();
		else if (!Preferences.NonInteractive)
			newPassword = AskPassword (_("Enter new password"), true);

		// New keyfiles
		if (!newKeyfiles.get() && !Preferences.NonInteractive)
		{
			if (keyfiles.get() && keyfiles->size() > 0 && AskYesNo (_("Keep current keyfiles?"), true))
				newKeyfiles = keyfiles;
			else
				newKeyfiles = AskKeyfiles (_("Enter new keyfile"));
		}

		Core->ChangePassword (volume, newPassword, newKeyfiles,
			newHash ? Pkcs5Kdf::GetAlgorithm (*newHash) : shared_ptr <Pkcs5Kdf>());

		ShowInfo ("PASSWORD_CHANGED");
	}
	
	void TextUserInterface::CheckInputStream ()
	{
		if (feof (stdin))
			throw UserAbort (SRC_POS);
	}

	void TextUserInterface::CreateVolume (shared_ptr <VolumeCreationOptions> options, const FilesystemPath &randomSourcePath) const
	{
		// Volume type
		if (options->Type == VolumeType::Unknown)
		{
			if (Preferences.NonInteractive)
			{
				options->Type = VolumeType::Normal;
			}
			else
			{
				ShowString (_("Volume type:\n 1) Normal\n 2) Hidden\n"));

				switch (AskSelection (2, 1))
				{
				case 1:
					options->Type = VolumeType::Normal;
					break;

				case 2:
					options->Type = VolumeType::Hidden;
					break;
				}
			}
		}

		shared_ptr <VolumeLayout> layout;
		if (options->Type == VolumeType::Hidden)
			layout.reset (new VolumeLayoutV2Hidden);
		else
			layout.reset (new VolumeLayoutV2Normal);

		if (!Preferences.NonInteractive && options->Type == VolumeType::Hidden)
			ShowInfo (_("\nIMPORTANT: Inexperienced users should use the graphical user interface to create a hidden volume. When using the text interface, the procedure described in the command line help must be followed to create a hidden volume."));

		// Volume path
		if (options->Path.IsEmpty())
		{
			if (Preferences.NonInteractive)
				throw MissingArgument (SRC_POS);

			do
			{
				ShowString (L"\n");
				options->Path = VolumePath (*AskVolumePath());
			} while (options->Path.IsEmpty());
		}

		// Volume size
		uint64 hostSize = 0;

		if (options->Type == VolumeType::Hidden)
		{
			FilesystemPath fsPath (wstring (options->Path));

			if (fsPath.IsFile())
			{
				File file;
				file.Open (fsPath);
				hostSize = file.Length();
			}
			else if (fsPath.IsDevice())
			{
				hostSize = Core->GetDeviceSize (fsPath);
			}
			else
			{
				throw_err (_("Hidden volume can be created only in an existing file or device."));
			}

			if (hostSize < TC_MIN_HIDDEN_VOLUME_HOST_SIZE)
				throw_err (StringFormatter (_("Minimum outer volume size is {0}."), SizeToString (TC_MIN_HIDDEN_VOLUME_HOST_SIZE + 512)));
		}

		if (options->Path.IsDevice() && options->Type != VolumeType::Hidden)
		{
			if (options->Size != 0)
				throw_err (_("Volume size cannot be changed for device-hosted volumes."));

			options->Size = Core->GetDeviceSize (options->Path);
		}
		else
		{
			options->Quick = false;

			while (options->Size == 0)
			{
				if (Preferences.NonInteractive)
					throw MissingArgument (SRC_POS);

				wstring sizeStr = AskString (options->Type == VolumeType::Hidden ? _("\nEnter hidden volume size (sizeK/size[M]/sizeG): ") : _("\nEnter volume size (sizeK/size[M]/sizeG): "));
				int multiplier = 1024 * 1024;

				if (sizeStr.find (L"K") != string::npos)
				{
					multiplier = 1024;
					sizeStr.resize (sizeStr.size() - 1);
				}
				else if (sizeStr.find (L"M") != string::npos)
				{
					sizeStr.resize (sizeStr.size() - 1);
				}
				else if (sizeStr.find (L"G") != string::npos)
				{
					multiplier = 1024 * 1024 * 1024;
					sizeStr.resize (sizeStr.size() - 1);
				}

				try
				{
					options->Size = StringConverter::ToUInt64 (sizeStr);
					options->Size *= multiplier;
				}
				catch (...)
				{
					continue;
				}

				uint64 minVolumeSize = options->Type == VolumeType::Hidden ? TC_MIN_HIDDEN_VOLUME_SIZE : TC_MIN_VOLUME_SIZE;

				if (options->Size < minVolumeSize)
				{
					ShowError (StringFormatter (_("Minimum volume size is {0}."), SizeToString (minVolumeSize + 512)));
					options->Size = 0;
				}
				
				if (options->Type == VolumeType::Hidden)
				{
					uint64 maxHiddenVolumeSize = VolumeLayoutV2Normal().GetMaxDataSize (hostSize) - TC_MIN_FAT_FS_SIZE;

					if (options->Size > maxHiddenVolumeSize)
					{
						ShowError (StringFormatter (_("Maximum volume size is {0}."), SizeToString (maxHiddenVolumeSize)));
						options->Size = 0;
					}
				}
			}
		}

		if (options->Type == VolumeType::Hidden)
			options->Quick = true;

		// Encryption algorithm
		if (!options->EA)
		{
			if (Preferences.NonInteractive)
				throw MissingArgument (SRC_POS);

			ShowInfo (wxString (L"\n") + LangString["ENCRYPTION_ALGORITHM_LV"] + L":");

			vector < shared_ptr <EncryptionAlgorithm> > encryptionAlgorithms;
			foreach (shared_ptr <EncryptionAlgorithm> ea, EncryptionAlgorithm::GetAvailableAlgorithms())
			{
				if (!ea->IsDeprecated())
				{
					ShowString (StringFormatter (L" {0}) {1}\n", (uint32) encryptionAlgorithms.size() + 1, ea->GetName()));
					encryptionAlgorithms.push_back (ea);
				}
			}


			options->EA = encryptionAlgorithms[AskSelection (encryptionAlgorithms.size(), 1) - 1];
		}

		// Hash algorithm
		if (!options->VolumeHeaderKdf)
		{
			if (Preferences.NonInteractive)
				throw MissingArgument (SRC_POS);

			ShowInfo (_("\nHash algorithm:"));

			vector < shared_ptr <Hash> > hashes;
			foreach (shared_ptr <Hash> hash, Hash::GetAvailableAlgorithms())
			{
				if (!hash->IsDeprecated())
				{
					ShowString (StringFormatter (L" {0}) {1}\n", (uint32) hashes.size() + 1, hash->GetName()));
					hashes.push_back (hash);
				}
			}

			shared_ptr <Hash> selectedHash = hashes[AskSelection (hashes.size(), 1) - 1];
			RandomNumberGenerator::SetHash (selectedHash);
			options->VolumeHeaderKdf = Pkcs5Kdf::GetAlgorithm (*selectedHash);

		}

		// Filesystem
		options->FilesystemClusterSize = 0;

		if (options->Filesystem == VolumeCreationOptions::FilesystemType::Unknown)
		{
			if (Preferences.NonInteractive)
			{
				options->Filesystem = VolumeCreationOptions::FilesystemType::FAT;
			}
			else
			{
				ShowInfo (_("\nFilesystem:\n 1) FAT\n 2) None"));

				switch (AskSelection (2, 1))
				{
				case 1:
					options->Filesystem = VolumeCreationOptions::FilesystemType::FAT;
					break;

				case 2:
					options->Filesystem = VolumeCreationOptions::FilesystemType::None;
					break;
				}
			}
		}

		uint64 filesystemSize = layout->GetMaxDataSize (options->Size);

		if (options->Filesystem == VolumeCreationOptions::FilesystemType::FAT
			&& (filesystemSize < TC_MIN_FAT_FS_SIZE || filesystemSize > TC_MAX_FAT_FS_SIZE))
		{
			throw_err (_("Specified volume size cannot be used with FAT filesystem."));
		}

		// Password
		if (!options->Password && !Preferences.NonInteractive)
		{
			ShowString (L"\n");
			options->Password = AskPassword (_("Enter password"), true);
		}

		if (options->Password)
			options->Password->CheckPortability();

		// Keyfiles
		if (!options->Keyfiles && !Preferences.NonInteractive)
		{
			ShowString (L"\n");
			options->Keyfiles = AskKeyfiles (_("Enter keyfile path"));
		}

		if ((!options->Keyfiles || options->Keyfiles->empty()) 
			&& (!options->Password || options->Password->IsEmpty()))
		{
			throw_err (_("Password cannot be empty when no keyfile is specified"));
		}

		// Random data
		RandomNumberGenerator::Start();
		finally_do ({ RandomNumberGenerator::Stop(); });

		if (!randomSourcePath.IsEmpty())
		{
			Buffer buffer (RandomNumberGenerator::PoolSize);
			File randSourceFile;
			
			randSourceFile.Open (randomSourcePath, File::OpenRead);

			for (size_t i = 0; i < buffer.Size(); ++i)
			{
				if (randSourceFile.Read (buffer.GetRange (i, 1)) < 1)
					break;
			}

			RandomNumberGenerator::AddToPool (buffer);
		}
		else if (!Preferences.NonInteractive)
		{
			int randCharsRequired = RandomNumberGenerator::PoolSize / 2;
			ShowInfo (StringFormatter (_("\nPlease type at least {0} randomly chosen characters and then press Enter:"), randCharsRequired));

			while (randCharsRequired > 0)
			{
				wstring randStr = AskString();
				RandomNumberGenerator::AddToPool (ConstBufferPtr ((byte *) randStr.c_str(), randStr.size()));

				randCharsRequired -= randStr.size();

				if (randCharsRequired > 0)
					ShowInfo (StringFormatter (_("Characters remaining: {0}"), randCharsRequired));
			}
		}

		ShowString (L"\n");
		wxLongLong startTime = wxGetLocalTimeMillis();

		VolumeCreator creator;
		creator.CreateVolume (options);

		bool volumeCreated = false;
		while (!volumeCreated)
		{
			VolumeCreator::ProgressInfo progress = creator.GetProgressInfo();

			wxLongLong timeDiff = wxGetLocalTimeMillis() - startTime;
			if (timeDiff.GetValue() > 0)
			{
				uint64 speed = progress.SizeDone * 1000 / timeDiff.GetValue();

				volumeCreated = !progress.CreationInProgress;

				ShowString (wxString::Format (L"\rDone: %7.3f%%  Speed: %9s  Left: %s         ",
					100.0 - double (options->Size - progress.SizeDone) / (double (options->Size) / 100.0),
					speed > 0 ? SpeedToString (speed).c_str() : L" ",
					speed > 0 ? TimeSpanToString ((options->Size - progress.SizeDone) / speed).c_str() : L""));
			}

			Thread::Sleep (100);
		}

		ShowString (L"\n\n");
		creator.CheckResult();

		ShowInfo (options->Type == VolumeType::Hidden ? "HIDVOL_FORMAT_FINISHED_HELP" : "FORMAT_FINISHED_INFO");
	}

	void TextUserInterface::DoShowError (const wxString &message) const
	{
		wcerr << L"Error: " << static_cast<wstring> (message) << endl;
	}

	void TextUserInterface::DoShowInfo (const wxString &message) const
	{
		wcout << static_cast<wstring> (message) << endl;
	}

	void TextUserInterface::DoShowString (const wxString &str) const
	{
		wcout << str.c_str();
	}

	void TextUserInterface::DoShowWarning (const wxString &message) const
	{
		wcerr << L"Warning: " << static_cast<wstring> (message) << endl;
	}

	shared_ptr <GetStringFunctor> TextUserInterface::GetAdminPasswordRequestHandler ()
	{
		struct AdminPasswordRequestHandler : public GetStringFunctor
		{
			AdminPasswordRequestHandler (TextUserInterface *userInterface) : UI (userInterface) { }
			virtual string operator() ()
			{
				UI->ShowString (_("Enter system administrator password: "));

				TextUserInterface::SetTerminalEcho (false);
				finally_do ({ TextUserInterface::SetTerminalEcho (true); });
				
				string password = StringConverter::ToSingle (wstring (UI->TextInputStream->ReadLine()));
				CheckInputStream();

				UI->ShowString (L"\n");
				return password;
			}
			TextUserInterface *UI;
		};
		
		return shared_ptr <GetStringFunctor> (new AdminPasswordRequestHandler (this));
	}

	VolumeInfoList TextUserInterface::MountAllDeviceHostedVolumes (MountOptions &options) const
	{
		while (true)
		{
			if (!options.Password)
				options.Password = AskPassword();

			if (!options.Keyfiles)
				options.Keyfiles = AskKeyfiles();

			VolumeInfoList mountedVolumes = UserInterface::MountAllDeviceHostedVolumes (options);
			
			if (!mountedVolumes.empty())
				return mountedVolumes;

			options.Password.reset();
		}
	}
	
	shared_ptr <VolumeInfo> TextUserInterface::MountVolume (MountOptions &options) const
	{
		shared_ptr <VolumeInfo> volume;

		CheckRequirementsForMountingVolume();

		// Volume path
		while (!options.Path || options.Path->IsEmpty())
		{
			if (Preferences.NonInteractive)
				throw MissingArgument (SRC_POS);

			options.Path = AskVolumePath ();
		}

		if (Core->IsVolumeMounted (*options.Path))
		{
			ShowInfo (StringFormatter (LangString["VOLUME_ALREADY_MOUNTED"], wstring (*options.Path)));
			return volume;
		}

		// Mount point
		if (!options.MountPoint && !options.NoFilesystem)
			options.MountPoint.reset (new DirectoryPath (AskString (_("Enter mount directory [default]: "))));
		
		VolumePassword password;
		KeyfileList keyfiles;

		if ((!options.Password || options.Password->IsEmpty())
			&& (!options.Keyfiles || options.Keyfiles->empty())
			&& !Core->IsPasswordCacheEmpty())
		{
			// Cached password
			try
			{
				volume = UserInterface::MountVolume (options);
			}
			catch (PasswordException&) { }
		}

		int incorrectPasswordCount = 0;

		while (!volume)
		{
			// Password
			if (!options.Password)
			{
				options.Password = AskPassword (StringFormatter (_("Enter password for {0}"), wstring (*options.Path)));
			}
			else
			{
				try
				{
					if (options.Password)
						options.Password->CheckPortability();
				}
				catch (UnportablePassword &)
				{
					ShowWarning ("UNSUPPORTED_CHARS_IN_PWD_RECOM");
				}
			}

			// Keyfiles
			if (!options.Keyfiles)
				options.Keyfiles = AskKeyfiles();

			// Hidden volume protection
			if (options.Protection == VolumeProtection::None
				&& !CmdLine->ArgNoHiddenVolumeProtection
				&& AskYesNo (_("Protect hidden volume?")))
				options.Protection = VolumeProtection::HiddenVolumeReadOnly;

			if (options.Protection == VolumeProtection::HiddenVolumeReadOnly)
			{
				if (!options.ProtectionPassword)
					options.ProtectionPassword = AskPassword (_("Enter password for hidden volume"));
				if (!options.ProtectionKeyfiles)
					options.ProtectionKeyfiles = AskKeyfiles (_("Enter keyfile for hidden volume"));
			}

			try
			{
				volume = UserInterface::MountVolume (options);
			}
			catch (ProtectionPasswordIncorrect &e)
			{
				ShowInfo (e);
				options.ProtectionPassword.reset();
			}
			catch (PasswordIncorrect &e)
			{
				if (++incorrectPasswordCount > 2 && !options.UseBackupHeaders)
				{
					// Try to mount the volume using the backup header
					options.UseBackupHeaders = true;

					try
					{
						volume = UserInterface::MountVolume (options);
						ShowWarning ("HEADER_DAMAGED_AUTO_USED_HEADER_BAK");
					}
					catch (...)
					{
						options.UseBackupHeaders = false;
						ShowInfo (e);
						options.Password.reset();
					}
				}
				else
				{
					ShowInfo (e);
					options.Password.reset();
				}
			}
			catch (PasswordException &e)
			{
				ShowInfo (e);
				options.Password.reset();
			}
		}

#ifdef TC_LINUX
		if (!Preferences.NonInteractive && !Preferences.DisableKernelEncryptionModeWarning && volume->EncryptionModeName != L"XTS")
			ShowWarning (LangString["ENCRYPTION_MODE_NOT_SUPPORTED_BY_KERNEL"]);
#endif

		return volume;
	}

	bool TextUserInterface::OnInit ()
	{
		try
		{
			DefaultMessageOutput = new wxMessageOutputStderr;
			wxMessageOutput::Set (DefaultMessageOutput);

			InterfaceType = UserInterfaceType::Text;
			Init();
		}
		catch (exception &e)
		{
			ShowError (e);
			return false;
		}
		return true;
	}

	int TextUserInterface::OnRun()
	{ 
		try
		{
			if (ProcessCommandLine ())
			{
				Application::SetExitCode (0);
				return 0;
			}
		}
		catch (exception &e)
		{
			ShowError (e);
		}

		Application::SetExitCode (1);
		return 1;
	}

	void TextUserInterface::OnSignal (int signal)
	{
#ifdef TC_UNIX
		try
		{
			SetTerminalEcho (true);
		}
		catch (...) { }
		_exit (1);
#endif
	}

	void TextUserInterface::SetTerminalEcho (bool enable)
	{
#ifdef TC_UNIX
		struct termios termAttr;
		if (tcgetattr (0, &termAttr) == 0)
		{
			if (!enable)
			{
				termAttr.c_lflag &= ~ECHO;
				throw_sys_if (tcsetattr (0, TCSANOW, &termAttr) != 0);
			}
			else
			{
				termAttr.c_lflag |= ECHO;
				throw_sys_if (tcsetattr (0, TCSANOW, &termAttr) != 0);
			}
		}
#endif
	}

	wxMessageOutput *DefaultMessageOutput;
}
