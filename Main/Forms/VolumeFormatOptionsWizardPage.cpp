/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.6 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "VolumeFormatOptionsWizardPage.h"

namespace TrueCrypt
{
	VolumeFormatOptionsWizardPage::VolumeFormatOptionsWizardPage (wxPanel* parent, uint64 volumeSize, bool enableQuickFormatButton, bool disableNoneFilesystem, bool disable32bitFilesystems)
		: VolumeFormatOptionsWizardPageBase (parent)
	{
		InfoStaticText->SetLabel (_(
			"In order to enable your operating system to mount your new volume, it has to be formatted with a filesystem. Please select a filesystem type.\n\nIf your volume is going to be hosted on a device or partition, you can use 'Quick format' to skip encryption of free space of the volume."));

		if (!disableNoneFilesystem)
			FilesystemTypeChoice->Append (LangString["NONE"],	(void *) VolumeCreationOptions::FilesystemType::None);

		if (!disable32bitFilesystems && volumeSize <= TC_MAX_FAT_FS_SIZE)
			FilesystemTypeChoice->Append (L"FAT",			(void *) VolumeCreationOptions::FilesystemType::FAT);

#ifdef TC_WINDOWS
		FilesystemTypeChoice->Append (L"NTFS",				(void *) VolumeCreationOptions::FilesystemType::NTFS);
#elif defined (TC_LINUX)
		FilesystemTypeChoice->Append (L"Linux Ext2",		(void *) VolumeCreationOptions::FilesystemType::Ext2);
		FilesystemTypeChoice->Append (L"Linux Ext3",		(void *) VolumeCreationOptions::FilesystemType::Ext3);
#elif defined (TC_MACOSX)
		FilesystemTypeChoice->Append (L"Mac OS Extended",	(void *) VolumeCreationOptions::FilesystemType::MacOsExt);
#elif defined (TC_FREEBSD)
		FilesystemTypeChoice->Append (L"UFS",				(void *) VolumeCreationOptions::FilesystemType::UFS);
#endif

		if (!disable32bitFilesystems && volumeSize <= TC_MAX_FAT_FS_SIZE)
			SetFilesystemType (VolumeCreationOptions::FilesystemType::FAT);
		else
			SetFilesystemType (VolumeCreationOptions::FilesystemType::GetPlatformNative());

		QuickFormatCheckBox->Enable (enableQuickFormatButton);
	}

	VolumeCreationOptions::FilesystemType::Enum VolumeFormatOptionsWizardPage::GetFilesystemType () const
	{
		return (VolumeCreationOptions::FilesystemType::Enum) (unsigned long long) (Gui->GetSelectedData <void> (FilesystemTypeChoice));
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
		case VolumeCreationOptions::FilesystemType::None:		FilesystemTypeChoice->SetStringSelection (LangString["NONE"]); break;
		case VolumeCreationOptions::FilesystemType::FAT:		FilesystemTypeChoice->SetStringSelection (L"FAT"); break;
		case VolumeCreationOptions::FilesystemType::NTFS:		FilesystemTypeChoice->SetStringSelection (L"NTFS"); break;
		case VolumeCreationOptions::FilesystemType::Ext2:		FilesystemTypeChoice->SetStringSelection (L"Linux Ext2"); break;
		case VolumeCreationOptions::FilesystemType::Ext3:		FilesystemTypeChoice->SetStringSelection (L"Linux Ext3"); break;
		case VolumeCreationOptions::FilesystemType::MacOsExt:	FilesystemTypeChoice->SetStringSelection (L"Mac OS Extended"); break;
		case VolumeCreationOptions::FilesystemType::UFS:		FilesystemTypeChoice->SetStringSelection (L"UFS"); break;

		default:
			throw ParameterIncorrect (SRC_POS);
		}
	}
}
