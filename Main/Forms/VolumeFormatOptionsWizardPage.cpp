/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "VolumeFormatOptionsWizardPage.h"

namespace TrueCrypt
{
	VolumeFormatOptionsWizardPage::VolumeFormatOptionsWizardPage (wxPanel* parent, bool enableQuickFormatButton)
		: VolumeFormatOptionsWizardPageBase (parent)
	{
		InfoStaticText->SetLabel (_(
			"In order to enable your operating system to mount your new volume, it has to be formatted with a filesystem. Please select a filesystem type.\n\nIf your volume is going to be hosted on a device or partition, you can use 'Quick format' to skip encryption of free space of the volume."));

		FilesystemTypeChoice->Append (L"FAT");
		FilesystemTypeChoice->Append (LangString["NONE"]);
		QuickFormatCheckBox->Enable (enableQuickFormatButton);
	}

	VolumeCreationOptions::FilesystemType::Enum VolumeFormatOptionsWizardPage::GetFilesystemType () const
	{
		if (FilesystemTypeChoice->GetSelection() == 0)
			return VolumeCreationOptions::FilesystemType::FAT;

		return VolumeCreationOptions::FilesystemType::None;
	}

	void VolumeFormatOptionsWizardPage::OnFilesystemTypeSelected (wxCommandEvent& event)
	{
	}

	void VolumeFormatOptionsWizardPage::OnQuickFormatCheckBoxClick (wxCommandEvent& event)
	{
		if (event.IsChecked())
		{
			QuickFormatCheckBox->SetValue (Gui->AskYesNo (LangString["WARN_QUICK_FORMAT"], false, true));
		}
	}

	void VolumeFormatOptionsWizardPage::SetFilesystemType (VolumeCreationOptions::FilesystemType::Enum type)
	{
		switch (type)
		{
		case VolumeCreationOptions::FilesystemType::FAT:
			FilesystemTypeChoice->SetStringSelection (L"FAT");
			break;

		case VolumeCreationOptions::FilesystemType::None:
			FilesystemTypeChoice->SetStringSelection (L"NONE");
			break;

		default:
			throw ParameterIncorrect (SRC_POS);
		}
	}
}
