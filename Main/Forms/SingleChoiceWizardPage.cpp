/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "System.h"
#include "Main/GraphicUserInterface.h"
#include "SingleChoiceWizardPage.h"

namespace TrueCrypt
{
	SingleChoiceWizardPage::SingleChoiceWizardPage (wxPanel* parent, const wxString &groupBoxText)
		: SingleChoiceWizardPageBase (parent)
	{
		if (!groupBoxText.empty())
		{
			OuterChoicesSizer->Remove (ChoicesSizer);
			ChoicesSizer = new wxStaticBoxSizer (wxVERTICAL, this, groupBoxText);
			OuterChoicesSizer->Add (ChoicesSizer, 0, wxEXPAND, 5);
		}
	}

	void SingleChoiceWizardPage::AddChoice (int id, const wxString &text)
	{
		assert (RadioButtonMap.find (id) == RadioButtonMap.end());
		wxRadioButton *radioButton = new wxRadioButton (this, wxID_ANY, text);
		if (RadioButtonMap.empty())
			radioButton->SetValue (1);

		RadioButtonMap[id] = radioButton;
		ChoicesSizer->Add (radioButton, 0, wxALL, 5);
	}

	int SingleChoiceWizardPage::GetSelection () const
	{
		typedef pair <int, wxRadioButton*> MapPair;
		foreach (MapPair p, RadioButtonMap)
		{
			if (p.second->GetValue())
				return p.first;
		}

		return -1;
	}

	void SingleChoiceWizardPage::SetSelection (int id)
	{
		typedef pair <int, wxRadioButton*> MapPair;
		foreach (MapPair p, RadioButtonMap)
		{
			if (p.first == id)
			{
				p.second->SetValue (true);
				return;
			}
		}
		throw ParameterIncorrect (SRC_POS);
	}
}
