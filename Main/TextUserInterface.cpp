/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
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
					if (password->Size() < VolumePassword::WarningSizeThreshold
						&& !AskYesNo (LangString ["PASSWORD_LENGTH_WARNING"], false, true))
						continue;
				}
			}

			if (!verify || verPhase)
				return password;

			if (!verPhase)
				verPhase = true;
		}

		return password;
	}

	wstring TextUserInterface::AskString (const wxString &message) const
	{
		ShowString (message);

		return wstring (TextInputStream->ReadLine());
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

	void TextUserInterface::ChangePassword (shared_ptr <VolumePath> volumePath, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, shared_ptr <VolumePassword> newPassword, shared_ptr <KeyfileList> newKeyfiles) const
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

		Core->ChangePassword (volume, newPassword, newKeyfiles);

		ShowInfo ("PASSWORD_CHANGED");
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

		// Volume path
		if (!options.Path)
			options.Path = AskVolumePath ();
		
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
			catch (PasswordException &e)
			{
				ShowInfo (e);
				options.Password.reset();
			}
		}

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

			SetExitOnFrameDelete (false);
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
