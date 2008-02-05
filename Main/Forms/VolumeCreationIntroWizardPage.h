/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_VolumeCreationIntroWizardPage
#define TC_HEADER_Main_Forms_VolumeCreationIntroWizardPage

#include "Forms.h"

namespace TrueCrypt
{
	class VolumeCreationIntroWizardPage : public VolumeCreationIntroWizardPageBase
	{
	public:
		VolumeCreationIntroWizardPage (wxPanel* parent);

		VolumeType::Enum GetSelection () const;
		bool IsValid () { return GetSelection() != VolumeType::Unknown; }
		void SetMaxStaticTextWidth (int width) { InfoStaticText->Wrap (width - 4); }
		void SetPageText (const wxString &text) { InfoStaticText->SetLabel (text); }
		void SetSelection (VolumeType::Enum volumeType);

	protected:
		void OnHiddenVolumeHyperlinkClick (wxHyperlinkEvent& event) { Gui->OpenHomepageLink (this, L"hiddenvolume"); }
	};
}

#endif // TC_HEADER_Main_Forms_VolumeCreationIntroWizardPage
