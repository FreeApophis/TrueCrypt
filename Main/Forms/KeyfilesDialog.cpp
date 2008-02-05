/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "KeyfilesDialog.h"

namespace TrueCrypt
{
	KeyfilesDialog::KeyfilesDialog (wxWindow* parent, shared_ptr <KeyfileList> keyfiles)
		: KeyfilesDialogBase (parent), Keyfiles (keyfiles)
	{
		mKeyfilesPanel = new KeyfilesPanel (this, keyfiles);
		PanelSizer->Add (mKeyfilesPanel, 1, wxALL | wxEXPAND);

		WarningStaticText->SetLabel (_("WARNING: If you lose a keyfile or if any bit of its first 1024 kilobytes changes, it will be impossible to mount volumes that use the keyfile!"));
		WarningStaticText->Wrap (Gui->GetCharWidth (this) * 15);

		Layout();
		Fit();

		KeyfilesNoteStaticText->SetLabel (_("Any kind of file (for example, .mp3, .jpg, .zip, .avi) may be used as a TrueCrypt keyfile. Note that TrueCrypt never modifies the keyfile contents. You can select more than one keyfile (the order does not matter). If you add a folder, all files found in it will be used as keyfiles."));
		KeyfilesNoteStaticText->Wrap (UpperSizer->GetSize().GetWidth() - Gui->GetCharWidth (this) * 2);

		Layout();
		Fit();
		Center();
	}
	
	void KeyfilesDialog::OnKeyfilesHyperlinkClick (wxHyperlinkEvent& event)
	{
		Gui->OpenHomepageLink (this, L"keyfiles");
	}
}
