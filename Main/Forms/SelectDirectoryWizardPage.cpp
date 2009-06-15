/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.7 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "SelectDirectoryWizardPage.h"

namespace TrueCrypt
{
	bool SelectDirectoryWizardPage::IsValid ()
	{
		if (!DirectoryTextCtrl->IsEmpty())
		{
			return FilesystemPath (DirectoryTextCtrl->GetValue()).IsDirectory();
		}

		return false;
	}
	
	void SelectDirectoryWizardPage::OnBrowseButtonClick (wxCommandEvent& event)
	{
		DirectoryPath dir = Gui->SelectDirectory (this);

		if (!dir.IsEmpty())
			DirectoryTextCtrl->SetValue (wstring (dir));
	}
}
