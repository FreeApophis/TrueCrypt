/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#include "System.h"
#ifdef TC_UNIX
#include <signal.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "Platform/Unix/Process.h"
#endif

#include "Common/SecurityToken.h"
#include "Core/RandomNumberGenerator.h"
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

		struct stat statBuf;
		if (fstat (0, &statBuf) != -1)
#endif
		{
			FInputStream.reset (new wxFFileInputStream (stdin));
			TextInputStream.reset (new wxTextInputStream (*FInputStream));
		}
	}

	TextUserInterface::~TextUserInterface ()
	{
		try
		{
			if (RandomNumberGenerator::IsRunning())
				RandomNumberGenerator::Stop();
		}
		catch (...) { }

#ifdef TC_UNIX
		signal (SIGHUP, SIG_DFL);
		signal (SIGINT, SIG_DFL);
		signal (SIGQUIT, SIG_DFL);
		signal (SIGTERM, SIG_DFL);
#endif
	}

	FilePath TextUserInterface::AskFilePath (const wxString &message) const
	{
		return AskString (!message.empty() ? message : wxString (_("Enter filename: ")));
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

			wxString passwordStr;
			ReadInputStreamLine (passwordStr);

			size_t length = passwordStr.size();

			ShowString (L"\n");

			if (!verPhase && length < 1)
			{
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
	
	ssize_t TextUserInterface::AskSelection (ssize_t optionCount, ssize_t defaultOption) const
	{
		while (true)
		{
			wstring selectionStr = AskString (defaultOption == -1 ? wxString (_("Select: ")) : wxString (wstring (StringFormatter (_("Select [{0}]: "), (uint32) defaultOption))));
			ssize_t selection;

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
		return wstring (ReadInputStreamLine());
	}
	
	bool TextUserInterface::AskYesNo (const wxString &message, bool defaultYes, bool warning) const
	{
		while (true)
		{
			wxString s = AskString (StringFormatter (L"{0} (y={1}/n={2}) [{3}]: ",
				message, LangString["YES"], LangString["NO"], LangString[defaultYes ? "YES" : "NO"]));

			if (s.IsSameAs (L'n', false) || s.IsSameAs (L"no", false) || (!defaultYes && s.empty()))
				return false;

			if (s.IsSameAs (L'y', false) || s.IsSameAs (L"yes", false) || (defaultYes && s.empty()))
				return true;
		};
	}

	shared_ptr <VolumePath> TextUserInterface::AskVolumePath (const wxString &message) const
	{
		return make_shared <VolumePath> (AskString (message.empty() ? wxString (_("Enter volume path: ")) : message));
	}

	void TextUserInterface::BackupVolumeHeaders (shared_ptr <VolumePath> volumePath) const
	{
		if (!volumePath)
			volumePath = AskVolumePath();

		if (!volumePath)
			throw UserAbort (SRC_POS);

#ifdef TC_WINDOWS
		if (Core->IsVolumeMounted (*volumePath))
			throw_err (LangString["DISMOUNT_FIRST"]);
#endif

		ShowInfo ("EXTERNAL_VOL_HEADER_BAK_FIRST_INFO");

		shared_ptr <Volume> normalVolume;
		shared_ptr <Volume> hiddenVolume;

		MountOptions normalVolumeMountOptions;
		MountOptions hiddenVolumeMountOptions;

		normalVolumeMountOptions.Path = volumePath;
		hiddenVolumeMountOptions.Path = volumePath;

		VolumeType::Enum volumeType = VolumeType::Normal;

		// Open both types of volumes
		while (true)
		{
			shared_ptr <Volume> volume;
			MountOptions *options = (volumeType == VolumeType::Hidden ? &hiddenVolumeMountOptions : &normalVolumeMountOptions);

			while (!volume)
			{
				ShowString (L"\n");
				options->Password = AskPassword (LangString[volumeType == VolumeType::Hidden ? "ENTER_HIDDEN_VOL_PASSWORD" : "ENTER_NORMAL_VOL_PASSWORD"]);
				options->Keyfiles = AskKeyfiles();

				try
				{
					volume = Core->OpenVolume (
						options->Path,
						options->PreserveTimestamps,
						options->Password,
						options->Keyfiles,
						options->Protection,
						options->ProtectionPassword,
						options->ProtectionKeyfiles,
						true,
						volumeType,
						options->UseBackupHeaders
						);
				}
				catch (PasswordException &e)
				{
					ShowInfo (e);
				}
			}

			if (volumeType == VolumeType::Hidden)
				hiddenVolume = volume;
			else
				normalVolume = volume;

			// Ask whether a hidden volume is present
			if (volumeType == VolumeType::Normal && AskYesNo (L"\n" + LangString["DOES_VOLUME_CONTAIN_HIDDEN"]))
			{
				volumeType = VolumeType::Hidden;
				continue;
			}

			break;
		}

		if (hiddenVolume)
		{
			if (typeid (*normalVolume->GetLayout()) == typeid (VolumeLayoutV1Normal) && typeid (*hiddenVolume->GetLayout()) != typeid (VolumeLayoutV1Hidden))
				throw ParameterIncorrect (SRC_POS);

			if (typeid (*normalVolume->GetLayout()) == typeid (VolumeLayoutV2Normal) && typeid (*hiddenVolume->GetLayout()) != typeid (VolumeLayoutV2Hidden))
				throw ParameterIncorrect (SRC_POS);
		}

		// Ask user to select backup file path
		wxString confirmMsg = L"\n" + LangString["CONFIRM_VOL_HEADER_BAK"] + L"\n";
		confirmMsg.Replace (L"%hs", L"%s");

		if (!AskYesNo (wxString::Format (confirmMsg, wstring (*volumePath).c_str()), true))
			return;

		ShowString (L"\n");

		FilePath filePath = AskFilePath();
		if (filePath.IsEmpty())
			throw UserAbort (SRC_POS);

		File backupFile;
		backupFile.Open (filePath, File::CreateWrite);

		RandomNumberGenerator::Start();
		UserEnrichRandomPool();

		// Re-encrypt volume header
		SecureBuffer newHeaderBuffer (normalVolume->GetLayout()->GetHeaderSize());
		Core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, normalVolume->GetHeader(), normalVolumeMountOptions.Password, normalVolumeMountOptions.Keyfiles);

		backupFile.Write (newHeaderBuffer);

		if (hiddenVolume)
		{
			// Re-encrypt hidden volume header
			Core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, hiddenVolume->GetHeader(), hiddenVolumeMountOptions.Password, hiddenVolumeMountOptions.Keyfiles);
		}
		else
		{
			// Store random data in place of hidden volume header
			shared_ptr <EncryptionAlgorithm> ea = normalVolume->GetEncryptionAlgorithm();
			Core->RandomizeEncryptionAlgorithmKey (ea);
			ea->Encrypt (newHeaderBuffer);
		}

		backupFile.Write (newHeaderBuffer);

		ShowString (L"\n");
		ShowInfo ("VOL_HEADER_BACKED_UP");
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

		if (volumePath->IsEmpty())
			throw UserAbort (SRC_POS);

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

		UserEnrichRandomPool();

		Core->ChangePassword (volume, newPassword, newKeyfiles,
			newHash ? Pkcs5Kdf::GetAlgorithm (*newHash) : shared_ptr <Pkcs5Kdf>());

		ShowInfo ("PASSWORD_CHANGED");
	}

	void TextUserInterface::CreateKeyfile (shared_ptr <FilePath> keyfilePath) const
	{
		FilePath path;

		RandomNumberGenerator::Start();
		UserEnrichRandomPool();

		if (keyfilePath)
		{
			Core->CreateKeyfile (*keyfilePath);
		}
		else
		{
			wstring fileName = AskFilePath();
			if (fileName.empty())
				return;

			Core->CreateKeyfile (fileName);
		}

		ShowInfo ("KEYFILE_CREATED");
	}

	void TextUserInterface::DeleteSecurityTokenKeyfiles () const
	{
		shared_ptr <KeyfileList> keyfiles = AskKeyfiles();
		if (keyfiles->empty())
			throw UserAbort();

		foreach_ref (const Keyfile &keyfile, *keyfiles)
		{
			SecurityToken::DeleteKeyfile (SecurityTokenKeyfilePath (FilePath (keyfile)));
		}
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

	void TextUserInterface::ExportSecurityTokenKeyfile () const
	{
		wstring keyfilePath = AskString (_("Enter security token keyfile path: "));

		if (keyfilePath.empty())
			throw UserAbort (SRC_POS);

		SecurityTokenKeyfile tokenKeyfile (keyfilePath);

		vector <byte> keyfileData;
		SecurityToken::GetKeyfileData (tokenKeyfile, keyfileData);

		BufferPtr keyfileDataBuf (&keyfileData.front(), keyfileData.size());
		finally_do_arg (BufferPtr, keyfileDataBuf, { finally_arg.Erase(); });
		
		FilePath exportFilePath = AskFilePath();

		if (exportFilePath.IsEmpty())
			throw UserAbort (SRC_POS);

		File keyfile;
		keyfile.Open (exportFilePath, File::CreateWrite);
		keyfile.Write (keyfileDataBuf);
	}

	shared_ptr <GetStringFunctor> TextUserInterface::GetAdminPasswordRequestHandler ()
	{
		struct AdminPasswordRequestHandler : public GetStringFunctor
		{
			AdminPasswordRequestHandler (TextUserInterface *userInterface) : UI (userInterface) { }
			virtual void operator() (string &passwordStr)
			{
				UI->ShowString (_("Enter your user password or administrator password: "));

				TextUserInterface::SetTerminalEcho (false);
				finally_do ({ TextUserInterface::SetTerminalEcho (true); });
				
				wstring wPassword (UI->ReadInputStreamLine());
				finally_do_arg (wstring *, &wPassword, { StringConverter::Erase (*finally_arg); });

				UI->ShowString (L"\n");

				StringConverter::ToSingle (wPassword, passwordStr);
			}
			TextUserInterface *UI;
		};
		
		return shared_ptr <GetStringFunctor> (new AdminPasswordRequestHandler (this));
	}

	void TextUserInterface::ImportSecurityTokenKeyfiles () const
	{
		list <SecurityTokenInfo> tokens = SecurityToken::GetAvailableTokens();

		if (tokens.empty())
			throw_err (LangString ["NO_TOKENS_FOUND"]);

		CK_SLOT_ID slotId;

		if (tokens.size() == 1)
		{
			slotId = tokens.front().SlotId;
		}
		else
		{
			foreach (const SecurityTokenInfo &token, tokens)
			{
				wstringstream tokenLabel;
				tokenLabel << L"[" << token.SlotId << L"] " << LangString["TOKEN_SLOT_ID"].c_str() << L" " << token.SlotId << L"  " << token.Label;

				ShowInfo (tokenLabel.str());
			}

			slotId = (CK_SLOT_ID) AskSelection (tokens.back().SlotId, tokens.front().SlotId);
		}

		shared_ptr <KeyfileList> keyfiles = AskKeyfiles();
		if (keyfiles->empty())
			throw UserAbort();

		foreach_ref (const Keyfile &keyfilePath, *keyfiles)
		{
			File keyfile;
			keyfile.Open (keyfilePath, File::OpenRead, File::ShareReadWrite, File::PreserveTimestamps);

			if (keyfile.Length() > 0)
			{
				vector <byte> keyfileData (keyfile.Length());
				BufferPtr keyfileDataBuf (&keyfileData.front(), keyfileData.size());

				keyfile.ReadCompleteBuffer (keyfileDataBuf);
				finally_do_arg (BufferPtr, keyfileDataBuf, { finally_arg.Erase(); });

				SecurityToken::CreateKeyfile (slotId, keyfileData, string (FilePath (keyfilePath).ToBaseName()));
			}
			else
				throw InsufficientData (SRC_POS, FilePath (keyfilePath));
		}
	}

	void TextUserInterface::InitSecurityTokenLibrary () const
	{
		if (Preferences.SecurityTokenModule.IsEmpty())
			throw_err (LangString ["NO_PKCS11_MODULE_SPECIFIED"]);

		struct PinRequestHandler : public GetPinFunctor
		{
			PinRequestHandler (const TextUserInterface *userInterface) : UI (userInterface) { }

			virtual void operator() (string &passwordStr)
			{
				if (UI->GetPreferences().NonInteractive)
					throw MissingArgument (SRC_POS);

				UI->ShowString (wxString::Format (LangString["ENTER_TOKEN_PASSWORD"], StringConverter::ToWide (passwordStr).c_str()) + L" ");

				TextUserInterface::SetTerminalEcho (false);
				finally_do ({ TextUserInterface::SetTerminalEcho (true); });
				
				wstring wPassword (UI->ReadInputStreamLine());
				finally_do_arg (wstring *, &wPassword, { StringConverter::Erase (*finally_arg); });

				UI->ShowString (L"\n");

				StringConverter::ToSingle (wPassword, passwordStr);
			}

			const TextUserInterface *UI;
		};

		struct WarningHandler : public SendExceptionFunctor
		{
			WarningHandler (const TextUserInterface *userInterface) : UI (userInterface) { }

			virtual void operator() (const Exception &e)
			{
				UI->ShowError (e);
			}

			const TextUserInterface *UI;
		};

		try
		{
			SecurityToken::InitLibrary (Preferences.SecurityTokenModule, auto_ptr <GetPinFunctor> (new PinRequestHandler (this)), auto_ptr <SendExceptionFunctor> (new WarningHandler (this)));
		}
		catch (Exception &e)
		{
			ShowError (e);
			throw_err (LangString ["PKCS11_MODULE_INIT_FAILED"]);
		}
	}

	void TextUserInterface::ListSecurityTokenKeyfiles () const
	{
		foreach (const SecurityTokenKeyfile &keyfile, SecurityToken::GetAvailableKeyfiles())
		{
			ShowString (wstring (SecurityTokenKeyfilePath (keyfile)));
			ShowString (L"\n");
		}
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
	
	shared_ptr <VolumeInfo> TextUserInterface::MountVolume (MountOptions &options)
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
				&& AskYesNo (_("Protect hidden volume (if any)?")))
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

				ShowString (L"\n");
			}
			catch (PasswordException &e)
			{
				ShowInfo (e);
				options.Password.reset();
			}
		}

#ifdef TC_LINUX
		if (!Preferences.NonInteractive && !Preferences.DisableKernelEncryptionModeWarning
			&& volume->EncryptionModeName != L"XTS"
			&& (volume->EncryptionModeName != L"LRW" || volume->EncryptionAlgorithmMinBlockSize != 16 || volume->EncryptionAlgorithmKeySize != 32))
		{
			ShowWarning (LangString["ENCRYPTION_MODE_NOT_SUPPORTED_BY_KERNEL"]);
		}
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

	void TextUserInterface::ReadInputStreamLine (wxString &line) const
	{
		if (!TextInputStream.get() || feof (stdin) || ferror (stdin))
			throw UserAbort (SRC_POS);

		line = TextInputStream->ReadLine();

		if (ferror (stdin) || (line.empty() && feof (stdin)))
			throw UserAbort (SRC_POS);
	}

	wxString TextUserInterface::ReadInputStreamLine () const
	{
		wxString line;
		ReadInputStreamLine (line);
		return line;
	}

	void TextUserInterface::RestoreVolumeHeaders (shared_ptr <VolumePath> volumePath) const
	{
		if (!volumePath)
			volumePath = AskVolumePath();

		if (!volumePath)
			throw UserAbort (SRC_POS);

#ifdef TC_WINDOWS
		if (Core->IsVolumeMounted (*volumePath))
			throw_err (LangString["DISMOUNT_FIRST"]);
#endif

		// Ask whether to restore internal or external backup
		bool restoreInternalBackup;

		ShowInfo (LangString["HEADER_RESTORE_EXTERNAL_INTERNAL"]);
		ShowInfo (L"\n1) " + LangString["HEADER_RESTORE_INTERNAL"]);
		ShowInfo (L"2) " + LangString["HEADER_RESTORE_EXTERNAL"] + L"\n");

		switch (AskSelection (2))
		{
		case 1:
			restoreInternalBackup = true;
			break;

		case 2:
			restoreInternalBackup = false;
			break;

		default:
			throw UserAbort (SRC_POS);
		}

		if (restoreInternalBackup)
		{
			// Restore header from the internal backup
			shared_ptr <Volume> volume;
			MountOptions options;
			options.Path = volumePath;

			while (!volume)
			{
				ShowString (L"\n");
				options.Password = AskPassword();
				options.Keyfiles = AskKeyfiles();

				try
				{
					volume = Core->OpenVolume (
						options.Path,
						options.PreserveTimestamps,
						options.Password,
						options.Keyfiles,
						options.Protection,
						options.ProtectionPassword,
						options.ProtectionKeyfiles,
						options.SharedAccessAllowed,
						VolumeType::Unknown,
						true
						);
				}
				catch (PasswordException &e)
				{
					ShowInfo (e);
				}
			}

			shared_ptr <VolumeLayout> layout = volume->GetLayout();
			if (typeid (*layout) == typeid (VolumeLayoutV1Normal) || typeid (*layout) == typeid (VolumeLayoutV1Hidden))
			{
				throw_err (LangString ["VOLUME_HAS_NO_BACKUP_HEADER"]);
			}

			RandomNumberGenerator::Start();
			UserEnrichRandomPool();

			// Re-encrypt volume header
			SecureBuffer newHeaderBuffer (volume->GetLayout()->GetHeaderSize());
			Core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, volume->GetHeader(), options.Password, options.Keyfiles);

			// Write volume header
			int headerOffset = volume->GetLayout()->GetHeaderOffset();
			shared_ptr <File> volumeFile = volume->GetFile();

			if (headerOffset >= 0)
				volumeFile->SeekAt (headerOffset);
			else
				volumeFile->SeekEnd (headerOffset);

			volumeFile->Write (newHeaderBuffer);
		}
		else
		{
			// Restore header from an external backup

			wxString confirmMsg = L"\n\n" + LangString["CONFIRM_VOL_HEADER_RESTORE"];
			confirmMsg.Replace (L"%hs", L"%s");

			if (!AskYesNo (wxString::Format (confirmMsg, wstring (*volumePath).c_str()), true, true))
				return;

			ShowString (L"\n");

			FilePath filePath = AskFilePath();
			if (filePath.IsEmpty())
				throw UserAbort (SRC_POS);

			File backupFile;
			backupFile.Open (filePath, File::OpenRead);

			uint64 headerSize;
			bool legacyBackup;

			// Determine the format of the backup file
			switch (backupFile.Length())
			{
			case TC_VOLUME_HEADER_GROUP_SIZE:
				headerSize = TC_VOLUME_HEADER_SIZE;
				legacyBackup = false;
				break;

			case TC_VOLUME_HEADER_SIZE_LEGACY * 2:
				headerSize = TC_VOLUME_HEADER_SIZE_LEGACY;
				legacyBackup = true;
				break;

			default:
				throw_err (LangString ["HEADER_BACKUP_SIZE_INCORRECT"]);
			}

			// Open the volume header stored in the backup file
			MountOptions options;

			shared_ptr <VolumeLayout> decryptedLayout;

			while (!decryptedLayout)
			{
				options.Password = AskPassword (L"\n" + LangString["ENTER_HEADER_BACKUP_PASSWORD"]);
				options.Keyfiles = AskKeyfiles();

				try
				{
					// Test volume layouts
					foreach (shared_ptr <VolumeLayout> layout, VolumeLayout::GetAvailableLayouts ())
					{
						if (layout->HasDriveHeader())
							continue;

						if (!legacyBackup && (typeid (*layout) == typeid (VolumeLayoutV1Normal) || typeid (*layout) == typeid (VolumeLayoutV1Hidden)))
							continue;

						if (legacyBackup && (typeid (*layout) == typeid (VolumeLayoutV2Normal) || typeid (*layout) == typeid (VolumeLayoutV2Hidden)))
							continue;

						SecureBuffer headerBuffer (layout->GetHeaderSize());
						backupFile.ReadAt (headerBuffer, layout->GetType() == VolumeType::Hidden ? layout->GetHeaderSize() : 0);

						// Decrypt header
						shared_ptr <VolumePassword> passwordKey = Keyfile::ApplyListToPassword (options.Keyfiles, options.Password);
						if (layout->GetHeader()->Decrypt (headerBuffer, *passwordKey, layout->GetSupportedKeyDerivationFunctions(), layout->GetSupportedEncryptionAlgorithms(), layout->GetSupportedEncryptionModes()))
						{
							decryptedLayout = layout;
							break;
						}
					}

					if (!decryptedLayout)
						throw PasswordIncorrect (SRC_POS);
				}
				catch (PasswordException &e)
				{
					ShowWarning (e);
				}
			}

			File volumeFile;
			volumeFile.Open (*volumePath, File::OpenReadWrite, File::ShareNone, File::PreserveTimestamps);
			
			RandomNumberGenerator::Start();
			UserEnrichRandomPool();

			// Re-encrypt volume header
			SecureBuffer newHeaderBuffer (decryptedLayout->GetHeaderSize());
			Core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, decryptedLayout->GetHeader(), options.Password, options.Keyfiles);

			// Write volume header
			int headerOffset = decryptedLayout->GetHeaderOffset();
			if (headerOffset >= 0)
				volumeFile.SeekAt (headerOffset);
			else
				volumeFile.SeekEnd (headerOffset);

			volumeFile.Write (newHeaderBuffer);

			if (decryptedLayout->HasBackupHeader())
			{
				// Re-encrypt backup volume header
				Core->ReEncryptVolumeHeaderWithNewSalt (newHeaderBuffer, decryptedLayout->GetHeader(), options.Password, options.Keyfiles);
				
				// Write backup volume header
				headerOffset = decryptedLayout->GetBackupHeaderOffset();
				if (headerOffset >= 0)
					volumeFile.SeekAt (headerOffset);
				else
					volumeFile.SeekEnd (headerOffset);

				volumeFile.Write (newHeaderBuffer);
			}
		}

		ShowString (L"\n");
		ShowInfo ("VOL_HEADER_RESTORED");
	}

	void TextUserInterface::SetTerminalEcho (bool enable)
	{
		if (CmdLine->ArgDisplayPassword)
			return;

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
	
	void TextUserInterface::UserEnrichRandomPool () const
	{
		RandomNumberGenerator::Start();

		if (RandomNumberGenerator::IsEnrichedByUser())
			return;

		if (CmdLine->ArgHash)
			RandomNumberGenerator::SetHash (CmdLine->ArgHash);

		if (!CmdLine->ArgRandomSourcePath.IsEmpty())
		{
			SecureBuffer buffer (RandomNumberGenerator::PoolSize);
			File randSourceFile;

			randSourceFile.Open (CmdLine->ArgRandomSourcePath, File::OpenRead);

			for (size_t i = 0; i < buffer.Size(); ++i)
			{
				if (randSourceFile.Read (buffer.GetRange (i, 1)) < 1)
					break;
			}

			RandomNumberGenerator::AddToPool (buffer);
			RandomNumberGenerator::SetEnrichedByUserStatus (true);
		}
		else if (!Preferences.NonInteractive)
		{
			int randCharsRequired = RandomNumberGenerator::PoolSize;
			ShowInfo (StringFormatter (_("\nPlease type at least {0} randomly chosen characters and then press Enter:"), randCharsRequired));

			SetTerminalEcho (false);
			finally_do ({ TextUserInterface::SetTerminalEcho (true); });

			while (randCharsRequired > 0)
			{
				wstring randStr = AskString();
				RandomNumberGenerator::AddToPool (ConstBufferPtr ((byte *) randStr.c_str(), randStr.size() * sizeof (wchar_t)));

				randCharsRequired -= randStr.size();

				if (randCharsRequired > 0)
					ShowInfo (StringFormatter (_("Characters remaining: {0}"), randCharsRequired));
			}

			ShowString (L"\n");
			RandomNumberGenerator::SetEnrichedByUserStatus (true);
		}
	}

	wxMessageOutput *DefaultMessageOutput;
}
