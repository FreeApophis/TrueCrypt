/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_VolumeFormatOptionsWizardPage
#define TC_HEADER_Main_Forms_VolumeFormatOptionsWizardPage

#include "Forms.h"
#include "Core/VolumeCreator.h"

namespace TrueCrypt
{
	class VolumeFormatOptionsWizardPage : public VolumeFormatOptionsWizardPageBase
	{
	public:
		VolumeFormatOptionsWizardPage (wxPanel* parent, const VolumePath &volumePath);

		VolumeCreationOptions::FilesystemType::Enum GetFilesystemType () const;
		bool IsValid () { return true; }
		bool IsQuickFormatEnabled () const { return QuickFormatCheckBox->IsChecked(); }
		void SetMaxStaticTextWidth (int width) { InfoStaticText->Wrap (width); }
		void SetFilesystemType (VolumeCreationOptions::FilesystemType::Enum type);
		void SetPageText (const wxString &text) { InfoStaticText->SetLabel (text); }
		void SetQuickFormat (bool enabled) { QuickFormatCheckBox->SetValue (enabled); }

	protected:
		void OnFilesystemTypeSelected (wxCommandEvent& event);
		void OnQuickFormatCheckBoxClick (wxCommandEvent& event);
	};
}

#endif // TC_HEADER_Main_Forms_VolumeFormatOptionsWizardPage
