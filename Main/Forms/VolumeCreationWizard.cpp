/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "System.h"
#ifdef TC_UNIX
#include <unistd.h>
#endif
#include "Core/RandomNumberGenerator.h"
#include "Main/Application.h"
#include "Main/GraphicUserInterface.h"
#include "Main/Resources.h"
#include "VolumeCreationWizard.h"
#include "EncryptionOptionsWizardPage.h"
#include "InfoWizardPage.h"
#include "ProgressWizardPage.h"
#include "SingleChoiceWizardPage.h"
#include "VolumeCreationProgressWizardPage.h"
#include "VolumeFormatOptionsWizardPage.h"
#include "VolumeLocationWizardPage.h"
#include "VolumePasswordWizardPage.h"
#include "VolumeSizeWizardPage.h"

namespace TrueCrypt
{
	VolumeCreationWizard::VolumeCreationWizard (wxWindow* parent)
		: WizardFrame (parent),
		DeviceWarningConfirmed (false),
		DisplayKeyInfo (true),
		QuickFormatEnabled (false),
		SelectedFilesystemClusterSize (0),
		SelectedFilesystemType (VolumeCreationOptions::FilesystemType::FAT),
		SelectedVolumeHostType (VolumeHostType::File),
		SelectedVolumeType (VolumeType::Normal),
		VolumeSize (0)
	{
		RandomNumberGenerator::Start();

		SetTitle (LangString["VOLUME_CREATION_WIZARD"]);
		SetImage (Resources::GetVolumeCreationWizardBitmap (Gui->GetCharHeight (this) * 21));
		SetMaxStaticTextWidth (55);

		SetStep (Step::VolumeHostType);

		class Timer : public wxTimer
		{
		public:
			Timer (VolumeCreationWizard *wizard) : Wizard (wizard) { }

			void Notify()
			{
				Wizard->OnRandomPoolUpdateTimer();
			}

			VolumeCreationWizard *Wizard;
		}; 

		RandomPoolUpdateTimer.reset (dynamic_cast <wxTimer *> (new Timer (this)));
		RandomPoolUpdateTimer->Start (200);
	}

	VolumeCreationWizard::~VolumeCreationWizard ()
	{
		RandomNumberGenerator::Stop();
	}

	WizardPage *VolumeCreationWizard::GetPage (WizardStep step)
	{
		switch (step)
		{
		case Step::VolumeHostType:
			{
				ClearHistory();

				OuterVolume = false;
				QuickFormatEnabled = false;

				SingleChoiceWizardPage <VolumeHostType::Enum> *page = new SingleChoiceWizardPage <VolumeHostType::Enum> (GetPageParent(), wxEmptyString, true);
				page->SetMinSize (wxSize (Gui->GetCharWidth (this) * 58, Gui->GetCharHeight (this) * 18 + 5));

				page->SetPageTitle (LangString["VOLUME_CREATION_WIZARD"]);

				page->AddChoice (VolumeHostType::File, _("Create a file container"), _("Creates a virtual encrypted disk within a file. Recommended for inexperienced users."), L"introcontainer", _("More information"));
				page->AddChoice (VolumeHostType::Device, _("Create a volume within a partition/&device"), _("Formats and encrypts a non-system partition, entire external or secondary drive, entire USB stick, etc."));

				page->SetSelection (SelectedVolumeHostType);
				return page;
			}

		case Step::VolumeType:
			{
				SingleChoiceWizardPage <VolumeType::Enum> *page = new SingleChoiceWizardPage <VolumeType::Enum> (GetPageParent(), wxEmptyString, true);
				page->SetPageTitle (LangString["VOLUME_TYPE_TITLE"]);

				page->AddChoice (VolumeType::Normal, _("Standard TrueCrypt volume"), LangString["NORMAL_VOLUME_TYPE_HELP"]);
				page->AddChoice (VolumeType::Hidden, _("Hi&dden TrueCrypt volume "), LangString["HIDDEN_VOLUME_TYPE_HELP"],
					L"hiddenvolume", _("More information about hidden volumes"));

				page->SetSelection (SelectedVolumeType);
				return page;
			}

		case Step::VolumeLocation:
			{
				VolumeLocationWizardPage *page = new VolumeLocationWizardPage (GetPageParent(), SelectedVolumeHostType, SelectedVolumeType == VolumeType::Hidden);
				page->SetPageTitle (LangString["VOLUME_LOCATION"]);

				if (SelectedVolumeType == VolumeType::Hidden)
					page->SetPageText (LangString[SelectedVolumeHostType == VolumeHostType::File ? "FILE_HELP_HIDDEN_HOST_VOL" : "DEVICE_HELP_HIDDEN_HOST_VOL"]);
				else
					page->SetPageText (LangString[SelectedVolumeHostType == VolumeHostType::File ? "FILE_HELP" : "DEVICE_HELP"]);

				page->SetVolumePath (SelectedVolumePath);
				return page;
			}
			
		case Step::EncryptionOptions:
			{
				EncryptionOptionsWizardPage *page = new EncryptionOptionsWizardPage (GetPageParent());
				
				if (OuterVolume)
					page->SetPageTitle (LangString["CIPHER_HIDVOL_HOST_TITLE"]);
				else if (SelectedVolumeType == VolumeType::Hidden)
					page->SetPageTitle (LangString["CIPHER_HIDVOL_TITLE"]);
				else
					page->SetPageTitle (LangString["CIPHER_TITLE"]);

				page->SetEncryptionAlgorithm (SelectedEncryptionAlgorithm);
				page->SetHash (SelectedHash);
				return page;
			}

		case Step::VolumeSize:
			{
				wxString freeSpaceText;
				const char *pageTitle;
				const char *pageText;

				if (OuterVolume)
				{
					pageTitle = "SIZE_HIDVOL_HOST_TITLE";
					pageText = "SIZE_HELP_HIDDEN_HOST_VOL";
				}
				else if (SelectedVolumeType == VolumeType::Hidden)
				{
					pageTitle = "SIZE_HIDVOL_TITLE";
					pageText = "SIZE_HELP_HIDDEN_VOL";
					freeSpaceText = StringFormatter (_("Maximum possible hidden volume size for this volume is {0}."), Gui->SizeToString (MaxHiddenVolumeSize));
				}
				else
				{
					pageTitle = "SIZE_TITLE";
					pageText = "VOLUME_SIZE_HELP";
				}

				VolumeSizeWizardPage *page = new VolumeSizeWizardPage (GetPageParent(), SelectedVolumePath, freeSpaceText);
				
				page->SetPageTitle (LangString[pageTitle]);
				page->SetPageText (LangString[pageText]);
				
				if (!OuterVolume && SelectedVolumeType == VolumeType::Hidden)
					page->SetMaxVolumeSize (MaxHiddenVolumeSize);
				else
					page->SetVolumeSize (VolumeSize);

				if (OuterVolume)
					page->SetMinVolumeSize (TC_MIN_HIDDEN_VOLUME_HOST_SIZE);
				else if (SelectedVolumeType == VolumeType::Hidden)
					page->SetMinVolumeSize (TC_MIN_HIDDEN_VOLUME_SIZE);
				else
					page->SetMinVolumeSize (TC_MIN_VOLUME_SIZE);

				return page;
			}

		case Step::VolumePassword:
			{
				VolumePasswordWizardPage *page = new VolumePasswordWizardPage (GetPageParent(), Password, Keyfiles);
				
				if (OuterVolume)
					page->SetPageTitle (LangString["PASSWORD_HIDVOL_HOST_TITLE"]);
				else if (SelectedVolumeType == VolumeType::Hidden)
					page->SetPageTitle (LangString["PASSWORD_HIDVOL_TITLE"]);
				else
					page->SetPageTitle (LangString["PASSWORD_TITLE"]);
				
				page->SetPageText (LangString[OuterVolume ? "PASSWORD_HIDDENVOL_HOST_HELP" : "PASSWORD_HELP"]);
				return page;
			}

		case Step::FormatOptions:
			{
				VolumeFormatOptionsWizardPage *page = new VolumeFormatOptionsWizardPage (GetPageParent(),
					SelectedVolumePath.IsDevice() && SelectedVolumeType != VolumeType::Hidden);

				page->SetPageTitle (_("Format Options"));
				page->SetFilesystemType (SelectedFilesystemType);
				
				if (!OuterVolume && SelectedVolumeType == VolumeType::Hidden)
					QuickFormatEnabled = true;
				page->SetQuickFormat (QuickFormatEnabled);

				return page;
			}
			
		case Step::CreationProgress:
			{
				VolumeCreationProgressWizardPage *page = new VolumeCreationProgressWizardPage (GetPageParent(), DisplayKeyInfo);

				if (OuterVolume)
					page->SetPageTitle (LangString["FORMAT_HIDVOL_HOST_TITLE"]);
				else if (SelectedVolumeType == VolumeType::Hidden)
					page->SetPageTitle (LangString["FORMAT_HIDVOL_TITLE"]);
				else
					page->SetPageTitle (LangString["FORMAT_TITLE"]);

				page->SetPageText (LangString["FORMAT_HELP"]);
				page->AbortEvent.Connect (EventConnector <VolumeCreationWizard> (this, &VolumeCreationWizard::OnAbortButtonClick));
				page->SetNextButtonText (LangString["FORMAT"]);
				return page;
			}

		case Step::VolumeCreatedInfo:
			{
				InfoWizardPage *page = new InfoWizardPage (GetPageParent());
				page->SetPageTitle (LangString["FORMAT_FINISHED_TITLE"]);
				page->SetPageText (LangString["FORMAT_FINISHED_HELP"]);
				
				SetCancelButtonText (_("Exit"));
				return page;
			}

		case Step::OuterVolumeContents:
			{
				ClearHistory();

				MountOptions mountOptions;
				mountOptions.NoKernelCrypto = true;
				mountOptions.Keyfiles = Keyfiles;
				mountOptions.Password = Password;
				mountOptions.Path = make_shared <VolumePath> (SelectedVolumePath);

				try
				{
					wxBusyCursor busy;
					Gui->SetActiveFrame (this);
					MountedOuterVolume = Core->MountVolume (mountOptions);
				}
				catch (exception &e)
				{
					Gui->SetActiveFrame (this);
					Gui->ShowError (e);

					Close();
					return new InfoWizardPage (GetPageParent());
				}
				
				struct OpenOuterVolumeFunctor : public Functor
				{
					OpenOuterVolumeFunctor (const DirectoryPath &outerVolumeMountPoint) : OuterVolumeMountPoint (outerVolumeMountPoint) { }
					
					virtual void operator() ()
					{
						Gui->OpenExplorerWindow (OuterVolumeMountPoint);
					}
					
					DirectoryPath OuterVolumeMountPoint;
				};

				InfoWizardPage *page = new InfoWizardPage (GetPageParent(), _("Open Outer Volume"),
					shared_ptr <Functor> (new OpenOuterVolumeFunctor (MountedOuterVolume->MountPoint)));

				page->SetPageTitle (LangString["HIDVOL_HOST_FILLING_TITLE"]);
				
				page->SetPageText (StringFormatter (
					_("Outer volume has been successfully created and mounted as '{0}'. To this volume you should now copy some sensitive-looking files that you actually do NOT want to hide. The files will be there for anyone forcing you to disclose your password. You will reveal only the password for this outer volume, not for the hidden one. The files that you really care about will be stored in the hidden volume, which will be created later on. When you finish copying, click Next. Do not dismount the volume.\n\nNote: After you click Next, the outer volume will be analyzed to determine the size of uninterrupted area of free space whose end is aligned with the end of the volume. This area will accommodate the hidden volume, so it will limit its maximum possible size. The procedure ensures no data on the outer volume are overwritten by the hidden volume."),
					wstring (MountedOuterVolume->MountPoint)));
				
				return page;
			}

		case Step::HiddenVolume:
			{
				ClearHistory();
				OuterVolume = false;

				InfoWizardPage *page = new InfoWizardPage (GetPageParent());
				page->SetPageTitle (LangString["HIDVOL_PRE_CIPHER_TITLE"]);
				page->SetPageText (LangString["HIDVOL_PRE_CIPHER_HELP"]);

				return page;
			}

		default:
			throw ParameterIncorrect (SRC_POS);
		}
	}

	void VolumeCreationWizard::OnAbortButtonClick (EventArgs &args)
	{
		AbortRequested = true;
	}

	void VolumeCreationWizard::OnMouseMotion (wxMouseEvent& event)
	{
		event.Skip();
		if (!IsWorkInProgress() && RandomNumberGenerator::IsRunning())
		{
			RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <byte *> (&event), sizeof (event)));
			
			long coord = event.GetX();
			RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <byte *> (&coord), sizeof (coord)));
			coord = event.GetY();
			RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <byte *> (&coord), sizeof (coord)));
		}
	}
	
	void VolumeCreationWizard::OnProgressTimer ()
	{
		if (!IsWorkInProgress())
			return;

		if (AbortRequested && !AbortConfirmationPending)
		{
			AbortConfirmationPending = true;
			if (Gui->AskYesNo (LangString ["FORMAT_ABORT"], true))
			{
				if (IsWorkInProgress() && Creator.get() != nullptr)
				{
					CreationAborted = true;
					Creator->Abort();
				}
			}
			AbortRequested = false;
			AbortConfirmationPending = false;
		}

		VolumeCreator::ProgressInfo progress = Creator->GetProgressInfo();
		
		VolumeCreationProgressWizardPage *page = dynamic_cast <VolumeCreationProgressWizardPage *> (GetCurrentPage());
		page->SetProgressValue (progress.SizeDone);

		if (!progress.CreationInProgress && !AbortConfirmationPending)
		{
			SetWorkInProgress (false);
			OnVolumeCreatorFinished ();
		}
	}
	
	void VolumeCreationWizard::OnRandomPoolUpdateTimer ()
	{	
		if (!IsWorkInProgress())
		{
			wxLongLong time = wxGetLocalTimeMillis();
			RandomNumberGenerator::AddToPool (ConstBufferPtr (reinterpret_cast <byte *> (&time), sizeof (time)));
		}
	}

	void VolumeCreationWizard::OnVolumeCreatorFinished ()
	{
		VolumeCreationProgressWizardPage *page = dynamic_cast <VolumeCreationProgressWizardPage *> (GetCurrentPage());

		ProgressTimer.reset();
		page->SetProgressState (false);

		Gui->EndInteractiveBusyState (this);
		SetWorkInProgress (false);
		UpdateControls();

		try
		{
			if (!CreationAborted)
			{
				Creator->CheckResult();

				if (OuterVolume)
				{
					SetStep (Step::OuterVolumeContents);
				}
				else
				{
					Gui->ShowInfo (SelectedVolumeType == VolumeType::Hidden ? "HIDVOL_FORMAT_FINISHED_HELP" : "FORMAT_FINISHED_INFO");
					SetStep (Step::VolumeCreatedInfo);
				}

				return;
			}
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}

		page->SetProgressValue (0);
		if (SelectedVolumeType == VolumeType::Normal && !SelectedVolumePath.IsDevice())
		{
			try
			{
				FilePath (wstring (SelectedVolumePath)).Delete();
			}
			catch (...) { }
		}
	}

	WizardFrame::WizardStep VolumeCreationWizard::ProcessPageChangeRequest (bool forward)
	{
		switch (GetCurrentStep())
		{
		case Step::VolumeHostType:
			{
				SingleChoiceWizardPage <VolumeHostType::Enum> *page = dynamic_cast <SingleChoiceWizardPage <VolumeHostType::Enum> *> (GetCurrentPage());
				
				try
				{
					SelectedVolumeHostType = page->GetSelection();
				}
				catch (NoItemSelected &)
				{
					return GetCurrentStep();
				}

				return Step::VolumeType;
			}

		case Step::VolumeType:
			{
				SingleChoiceWizardPage <VolumeType::Enum> *page = dynamic_cast <SingleChoiceWizardPage <VolumeType::Enum> *> (GetCurrentPage());

				try
				{
					SelectedVolumeType = page->GetSelection();
				}
				catch (NoItemSelected &)
				{
					return GetCurrentStep();
				}

				if (SelectedVolumeType == VolumeType::Hidden)
					OuterVolume = true;

				return Step::VolumeLocation;
			}

		case Step::VolumeLocation:
			{
				VolumeLocationWizardPage *page = dynamic_cast <VolumeLocationWizardPage *> (GetCurrentPage());
				SelectedVolumePath = page->GetVolumePath();
				VolumeSize = 0;

				if (forward)
				{
					if (Core->IsVolumeMounted (SelectedVolumePath))
					{
						Gui->ShowInfo ("DISMOUNT_FIRST");
						return GetCurrentStep();
					}

					if (SelectedVolumePath.IsDevice())
					{
						if (!DeviceWarningConfirmed && !Gui->AskYesNo (LangString["FORMAT_DEVICE_FOR_ADVANCED_ONLY"]))
							return GetCurrentStep();

						DeviceWarningConfirmed = true;

						try
						{
							VolumeSize = Core->GetDeviceSize (SelectedVolumePath);
						}
						catch (UserAbort&)
						{
							return Step::VolumeLocation;
						}
						catch (exception &e)
						{
							Gui->ShowError (e);
							Gui->ShowError ("CANNOT_CALC_SPACE");
							return GetCurrentStep();
						}

						DirectoryPath mountPoint;
						try
						{
							mountPoint = Core->GetDeviceMountPoint (SelectedVolumePath);
							
							if (!mountPoint.IsEmpty())
							{
								Gui->ShowError (StringFormatter (_("The filesystem of the selected device is currently mounted. Please dismount '{0}' before proceeding."), wstring (mountPoint)));
								return GetCurrentStep();
							}
						}
						catch (...) { }
					}
				}

				return Step::EncryptionOptions;
			}
			
		case Step::EncryptionOptions:
			{
				EncryptionOptionsWizardPage *page = dynamic_cast <EncryptionOptionsWizardPage *> (GetCurrentPage());
				SelectedEncryptionAlgorithm = page->GetEncryptionAlgorithm ();
				SelectedHash = page->GetHash ();

				if (forward)
					RandomNumberGenerator::SetHash (SelectedHash);

				if (SelectedVolumePath.IsDevice() && (OuterVolume || SelectedVolumeType != VolumeType::Hidden))
					return Step::VolumePassword;
				else
					return Step::VolumeSize;
			}
			
		case Step::VolumeSize:
			{
				VolumeSizeWizardPage *page = dynamic_cast <VolumeSizeWizardPage *> (GetCurrentPage());

				try
				{
					VolumeSize = page->GetVolumeSize();
				}
				catch (Exception &e)
				{
					if (forward)
					{
						Gui->ShowError (e);
						return GetCurrentStep();
					}
				}

				if (forward
					&& !OuterVolume && SelectedVolumeType == VolumeType::Hidden
					&& (double) VolumeSize / MaxHiddenVolumeSize > 0.85)
				{
					if (!Gui->AskYesNo (LangString["FREE_SPACE_FOR_WRITING_TO_OUTER_VOLUME"]))
						return GetCurrentStep();
				}

				return Step::VolumePassword;
			}

		case Step::VolumePassword:
			{
				VolumePasswordWizardPage *page = dynamic_cast <VolumePasswordWizardPage *> (GetCurrentPage());
				Password = page->GetPassword();
				Keyfiles = page->GetKeyfiles();

				if (forward && Password && !Password->IsEmpty())
				{
					try
					{
						Password->CheckPortability();
					}
					catch (UnportablePassword &e)
					{
						Gui->ShowError (e);
						return GetCurrentStep();
					}

					if (Password->Size() < VolumePassword::WarningSizeThreshold
						&& !Gui->AskYesNo (LangString["PASSWORD_LENGTH_WARNING"], false, true))
					{
						return GetCurrentStep();
					}
				}

				if (OuterVolume)
				{
					SelectedFilesystemType = VolumeCreationOptions::FilesystemType::FAT;
					QuickFormatEnabled = false;
					return Step::CreationProgress;
				}

				return Step::FormatOptions;
			}

		case Step::FormatOptions:
			{
				VolumeFormatOptionsWizardPage *page = dynamic_cast <VolumeFormatOptionsWizardPage *> (GetCurrentPage());
				SelectedFilesystemType = page->GetFilesystemType();
				QuickFormatEnabled = page->IsQuickFormatEnabled();

				return Step::CreationProgress;
			}

			
		case Step::CreationProgress:
			{
				VolumeCreationProgressWizardPage *page = dynamic_cast <VolumeCreationProgressWizardPage *> (GetCurrentPage());

				DisplayKeyInfo = page->IsKeyInfoDisplayed();

				if (forward)
				{
					if (SelectedVolumeType != VolumeType::Hidden || OuterVolume)
					{
						if (SelectedVolumePath.IsDevice())
						{
							wxString confirmMsg = LangString["OVERWRITEPROMPT_DEVICE"];
							confirmMsg.Replace (L"%hs", L"%s");

							if (!Gui->AskYesNo (wxString::Format (confirmMsg, wxString (_("DEVICE")).c_str(), wstring (SelectedVolumePath).c_str(), L""), false, true))
								return GetCurrentStep();
						}
						else if (FilesystemPath (wstring (SelectedVolumePath)).IsFile())
						{
							wxString confirmMsg = LangString["OVERWRITEPROMPT"];
							confirmMsg.Replace (L"%hs", L"%s");

							if (!Gui->AskYesNo (wxString::Format (confirmMsg, wstring (SelectedVolumePath).c_str(), false, true)))
								return GetCurrentStep();
						}
					}

					AbortRequested = false;
					AbortConfirmationPending = false;
					CreationAborted = false;
					SetWorkInProgress (true);
					UpdateControls();

					Gui->BeginInteractiveBusyState (this);

					try
					{
						make_shared_auto (VolumeCreationOptions, options);

						options->Filesystem = SelectedFilesystemType;
						options->FilesystemClusterSize = SelectedFilesystemClusterSize;

						options->EA = SelectedEncryptionAlgorithm;
						options->Password = Password;
						options->Keyfiles = Keyfiles;
						options->Path = SelectedVolumePath;
						options->Quick = QuickFormatEnabled;
						options->Size = VolumeSize;
						options->Type = OuterVolume ? VolumeType::Normal : SelectedVolumeType;
						options->VolumeHeaderKdf = Pkcs5Kdf::GetAlgorithm (*SelectedHash);

						Creator.reset (new VolumeCreator);
						Creator->CreateVolume (options);

						page->SetKeyInfo (Creator->GetKeyInfo());

						class Timer : public wxTimer
						{
						public:
							Timer (VolumeCreationWizard *wizard) : Wizard (wizard) { }

							void Notify()
							{
								Wizard->OnProgressTimer();
							}

							VolumeCreationWizard *Wizard;
						}; 

						page->SetProgressRange (options->Size);
						page->SetProgressState (true);
						ProgressTimer.reset (dynamic_cast <wxTimer *> (new Timer (this)));
						ProgressTimer->Start (50);
					}
					catch (Exception &e)
					{
						CreationAborted = true;
						OnVolumeCreatorFinished();
						Gui->ShowError (e);
					}
				}

				return GetCurrentStep();
			}

		case Step::VolumeCreatedInfo:
			Creator.reset();
			SetCancelButtonText (L"");

			return Step::VolumeHostType;

		case Step::OuterVolumeContents:
			try
			{
				// Determine maximum size of the hidden volume
				wxBusyCursor busy;
#ifdef TC_UNIX
				sync();
#endif
				VolumeInfoList ml = Core->GetMountedVolumes (MountedOuterVolume->Path);
				MaxHiddenVolumeSize = 0;

				if (ml.empty())
					throw ParameterIncorrect (SRC_POS);

				if (ml.front()->TopWriteOffset == 0)
					throw_err (_("The outer volume does not contain any files."));

				Gui->SetActiveFrame (this);
				shared_ptr <VolumeInfo> dismountedOuterVolume = Core->DismountVolume (MountedOuterVolume, false, true);

				if (dismountedOuterVolume->Size > dismountedOuterVolume->TopWriteOffset)
					MaxHiddenVolumeSize = dismountedOuterVolume->Size - dismountedOuterVolume->TopWriteOffset;

				// Add a reserve (in case the user mounts the outer volume and creates new files
				// on it by accident or OS writes some new data behind his or her back, such as
				// System Restore etc.)

				uint64 reservedSize = dismountedOuterVolume->Size / 200;
				if (reservedSize > 10 * BYTES_PER_MB)
					reservedSize = 10 * BYTES_PER_MB;
	
				if (MaxHiddenVolumeSize < reservedSize)
					MaxHiddenVolumeSize = 0;
				else
					MaxHiddenVolumeSize -= reservedSize;

				MaxHiddenVolumeSize -= MaxHiddenVolumeSize % SECTOR_SIZE;		// Must be a multiple of the sector size
			}
			catch (exception &e)
			{
				Gui->SetActiveFrame (this);
				Gui->ShowError (e);
				return GetCurrentStep();
			}

			return Step::HiddenVolume;

		case Step::HiddenVolume:
			return Step::EncryptionOptions;

		default:
			throw ParameterIncorrect (SRC_POS);
		}
	}

	void VolumeCreationWizard::UpdateControls ()
	{
		VolumeCreationProgressWizardPage *page = dynamic_cast <VolumeCreationProgressWizardPage *> (GetCurrentPage());
		if (page)
		{
			page->EnableAbort (IsWorkInProgress());
		}
	}
}
