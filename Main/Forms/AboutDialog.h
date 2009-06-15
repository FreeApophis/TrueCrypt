/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.7 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_AboutDialog
#define TC_HEADER_Main_Forms_AboutDialog

#include "Forms.h"

namespace TrueCrypt
{
	class AboutDialog : public AboutDialogBase
	{
	public:
		AboutDialog (wxWindow* parent);
		
		void OnDonationsButtonClick (wxCommandEvent& event) { Gui->OpenHomepageLink (this, L"donate"); }
		void OnWebsiteHyperlinkClick (wxHyperlinkEvent& event) { Gui->OpenHomepageLink (this, L"main"); }
	};
}

#endif // TC_HEADER_Main_Forms_AboutDialog
