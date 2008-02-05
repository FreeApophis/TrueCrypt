/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifndef TC_HEADER_Main_Forms_VolumeCreationWizard
#define TC_HEADER_Main_Forms_VolumeCreationWizard

#include "WizardFrame.h"
#include "Core/VolumeCreator.h"

namespace TrueCrypt
{
	class VolumeCreationWizard : public WizardFrame
	{
	public:
		VolumeCreationWizard (wxWindow* parent);
		~VolumeCreationWizard ();

	protected:
		struct Step
		{
			enum Enum
			{
				VolumeType,
				VolumeLocation,
				VolumeSize,
				EncryptionOptions,
				VolumePassword,
				FormatOptions,
				CreationProgress,
				VolumeCreatedInfo
			};
		};

		void CreateVolume ();
		WizardPage *GetPage (WizardStep step);
		void OnAbortButtonClick (EventArgs &args);
		void OnMouseMotion (wxMouseEvent& event);
		void OnProgressTimer ();
		void OnRandomPoolUpdateTimer ();
		void OnThreadExiting (wxCommandEvent& event);
		void OnVolumeCreatorFinished ();
		WizardStep ProcessPageChangeRequest (bool forward);

		volatile bool AbortConfirmationPending;
		volatile bool AbortRequested;
		volatile bool CreationAborted;
		auto_ptr <VolumeCreator> Creator;
		bool DeviceWarningConfirmed;
		bool DisplayKeyInfo;
		auto_ptr <wxTimer> ProgressTimer;
		auto_ptr <wxTimer> RandomPoolUpdateTimer;
		shared_ptr <KeyfileList> Keyfiles;
		bool QuickFormatEnabled;
		shared_ptr <EncryptionAlgorithm> SelectedEncryptionAlgorithm;
		uint32 SelectedFilesystemClusterSize;
		VolumeCreationOptions::FilesystemType::Enum SelectedFilesystemType;
		VolumePath SelectedVolumePath;
		VolumeType::Enum SelectedVolumeType;
		shared_ptr <VolumePassword> Password;
		shared_ptr <Hash> SelectedHash;
		uint64 VolumeSize;

	private:
		void UpdateControls ();
	};
}

#endif // TC_HEADER_Main_Forms_VolumeCreationWizard
