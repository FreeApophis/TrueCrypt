/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Main_TextUserInterface
#define TC_HEADER_Main_TextUserInterface

#include "System.h"
#include "Main.h"
#include "UserInterface.h"

namespace TrueCrypt
{
	class TextUserInterface : public UserInterface
	{
	public:
		TextUserInterface ();
		virtual ~TextUserInterface ();

		virtual shared_ptr <KeyfileList> AskKeyfiles (const wxString &message = L"") const;
		virtual shared_ptr <VolumePassword> AskPassword (const wxString &message = L"", bool verify = false) const;
		virtual wstring AskString (const wxString &message) const;
		virtual shared_ptr <VolumePath> AskVolumePath (const wxString &message = L"") const;
		virtual bool AskYesNo (const wxString &message, bool defaultYes = false, bool warning = false) const;
		virtual void BeginBusyState () const { }
		virtual void ChangePassword (shared_ptr <VolumePath> volumePath = shared_ptr <VolumePath>(), shared_ptr <VolumePassword> password = shared_ptr <VolumePassword>(), shared_ptr <KeyfileList> keyfiles = shared_ptr <KeyfileList>(), shared_ptr <VolumePassword> newPassword = shared_ptr <VolumePassword>(), shared_ptr <KeyfileList> newKeyfiles = shared_ptr <KeyfileList>()) const;
		virtual void DoShowError (const wxString &message) const;
		virtual void DoShowInfo (const wxString &message) const;
		virtual void DoShowString (const wxString &str) const;
		virtual void DoShowWarning (const wxString &message) const;
		virtual void EndBusyState () const { }
		virtual shared_ptr <GetStringFunctor> GetAdminPasswordRequestHandler ();
#ifdef __WXGTK__
		virtual bool Initialize (int &argc, wxChar **argv) { return wxAppBase::Initialize(argc, argv); }
#endif
		virtual VolumeInfoList MountAllDeviceHostedVolumes (MountOptions &options) const;
		virtual shared_ptr <VolumeInfo> MountVolume (MountOptions &options) const;
		virtual bool OnInit ();
		virtual int OnRun();
		static void SetTerminalEcho (bool enable);
		virtual void Yield () const { }

	protected:
		static void OnSignal (int signal);

		auto_ptr <wxFFileInputStream> FInputStream;
		auto_ptr <wxTextInputStream> TextInputStream;

	private:
		TextUserInterface (const TextUserInterface &);
		TextUserInterface &operator= (const TextUserInterface &);
	};

	extern wxMessageOutput *DefaultMessageOutput;
}

#endif // TC_HEADER_Main_TextUserInterface
