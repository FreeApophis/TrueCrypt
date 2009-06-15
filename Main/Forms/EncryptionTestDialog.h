/*
Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

Governed by the TrueCrypt License 2.7 the full text of which is contained
in the file License.txt included in TrueCrypt binary and source code
distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_EncryptionTestDialog
#define TC_HEADER_Main_Forms_EncryptionTestDialog

#include "Forms.h"
#include "Main/Main.h"

namespace TrueCrypt
{
	class EncryptionTestDialog : public EncryptionTestDialogBase
	{
	public:
		EncryptionTestDialog (wxWindow* parent);

	protected:
		void EncryptOrDecrypt (bool encrypt);
		shared_ptr <EncryptionAlgorithm> GetSelectedEncryptionAlgorithm () const;
		void GetTextCtrlData (wxTextCtrl *textCtrl, Buffer &buffer) const;
		void OnAutoTestAllButtonClick (wxCommandEvent& event);
		void OnDecryptButtonClick (wxCommandEvent& event) { EncryptOrDecrypt (false); }
		void OnEncryptButtonClick (wxCommandEvent& event) { EncryptOrDecrypt (true); }
		void OnEncryptionAlgorithmSelected ();
		void OnEncryptionAlgorithmSelected (wxCommandEvent& event) { OnEncryptionAlgorithmSelected(); }
		void OnResetButtonClick (wxCommandEvent& event) { Reset(); }
		void OnXtsModeCheckBoxClick (wxCommandEvent& event);
		void SetTextCtrlData (wxTextCtrl *textCtrl, const BufferPtr &data);
		void Reset ();

		EncryptionAlgorithmList EncryptionAlgorithms;
	};
}

#endif // TC_HEADER_Main_Forms_EncryptionTestDialog
