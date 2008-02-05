/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_SingleChoiceWizardPage
#define TC_HEADER_Main_Forms_SingleChoiceWizardPage

#include "Forms.h"

namespace TrueCrypt
{
	class SingleChoiceWizardPage : public SingleChoiceWizardPageBase
	{
	public:
		SingleChoiceWizardPage (wxPanel* parent, const wxString &groupBoxText = wxEmptyString);

		void AddChoice (int id, const wxString &text);
		int GetSelection () const;
		bool IsValid () { return true; }
		void SetMaxStaticTextWidth (int width) { InfoStaticText->Wrap (width); }
		void SetPageText (const wxString &text) { InfoStaticText->SetLabel (text); }
		void SetSelection (int id);

	protected:
		map <int, wxRadioButton*> RadioButtonMap;
	};
}

#endif // TC_HEADER_Main_Forms_SingleChoiceWizardPage
