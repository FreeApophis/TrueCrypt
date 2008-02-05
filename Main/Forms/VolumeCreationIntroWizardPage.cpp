/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "VolumeCreationIntroWizardPage.h"

namespace TrueCrypt
{
	VolumeCreationIntroWizardPage::VolumeCreationIntroWizardPage (wxPanel* parent)
		: VolumeCreationIntroWizardPageBase (parent)
	{
	}

	VolumeType::Enum VolumeCreationIntroWizardPage::GetSelection () const
	{
		if (StandardVolumeRadioButton->GetValue())
			return VolumeType::Normal;

		if (HiddenVolumeRadioButton->GetValue())
			return VolumeType::Hidden;

		return VolumeType::Unknown;
	}

	void VolumeCreationIntroWizardPage::SetSelection (VolumeType::Enum volumeType)
	{
		if (volumeType == VolumeType::Hidden)
			HiddenVolumeRadioButton->SetValue (true);
		else
			StandardVolumeRadioButton->SetValue (true);
	}
}
