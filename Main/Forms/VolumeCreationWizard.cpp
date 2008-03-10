
#include "System.h"
#include "Core/RandomNumberGenerator.h"
#include "Main/Application.h"
#include "Main/GraphicUserInterface.h"
#include "Main/Resources.h"
#include "VolumeCreationWizard.h"
#include "EncryptionOptionsWizardPage.h"
#include "InfoWizardPage.h"
#include "ProgressWizardPage.h"
#include "SingleChoiceWizardPage.h"
#include "VolumeCreationIntroWizardPage.h"
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
		SelectedVolumeType (VolumeType::Normal),
		VolumeSize (0)
	{
		RandomNumberGenerator::Start();

		SetTitle (LangString["VOLUME_CREATION_WIZARD"]);
		SetImage (Resources::GetVolumeCreationWizardBitmap (Gui->GetCharHeight (this) * 21));
		SetMaxStaticTextWidth (55);

		SetStep (Step::VolumeType);

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
		case Step::VolumeType:
			{
				ClearHistory();

				VolumeCreationIntroWizardPage *page = new VolumeCreationIntroWizardPage (GetPageParent());
				page->SetMinSize (wxSize (Gui->GetCharWidth (this) * 58, Gui->GetCharHeight (this) * 18 + 5));

				page->SetPageTitle (LangString["VOLUME_CREATION_WIZARD"]);
				page->SetPageText (LangString["VOLUME_CREATION_INTRO"]);

				page->SetSelection (SelectedVolumeType);
				return page;
			}

		case Step::VolumeLocation:
			{
				VolumeLocationWizardPage *page = new VolumeLocationWizardPage (GetPageParent());
				page->SetPageTitle (LangString["VOLUME_LOCATION"]);
				page->SetPageText (LangString["VOLUME_LOCATION_WIZARD_PAGE_INFO"]);

				page->SetVolumePath (SelectedVolumePath);
				return page;
			}

		case Step::VolumeSize:
			{
				VolumeSizeWizardPage *page = new VolumeSizeWizardPage (GetPageParent(), SelectedVolumePath);
				page->SetPageTitle (LangString["SIZE_TITLE"]);
				page->SetPageText (LangString["VOLUME_SIZE_HELP"]);
				page->SetVolumeSize (VolumeSize);
				return page;
			}

		case Step::EncryptionOptions:
			{
				EncryptionOptionsWizardPage *page = new EncryptionOptionsWizardPage (GetPageParent());
				page->SetPageTitle (LangString["CIPHER_TITLE"]);
				page->SetEncryptionAlgorithm (SelectedEncryptionAlgorithm);
				page->SetHash (SelectedHash);
				return page;
			}

		case Step::VolumePassword:
			{
				VolumePasswordWizardPage *page = new VolumePasswordWizardPage (GetPageParent(), Password, Keyfiles);
				page->SetPageTitle (LangString["PASSWORD_TITLE"]);
				page->SetPageText (LangString["PASSWORD_HELP"]);
				return page;
			}

		case Step::FormatOptions:
			{
				VolumeFormatOptionsWizardPage *page = new VolumeFormatOptionsWizardPage (GetPageParent(), SelectedVolumePath);
				page->SetPageTitle (_("Format Options"));
				page->SetFilesystemType (SelectedFilesystemType);
				page->SetQuickFormat (QuickFormatEnabled);
				return page;
			}
			
		case Step::CreationProgress:
			{
				VolumeCreationProgressWizardPage *page = new VolumeCreationProgressWizardPage (GetPageParent(), DisplayKeyInfo);
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
				Gui->ShowInfo ("FORMAT_FINISHED_INFO");
				SetStep (Step::VolumeCreatedInfo);
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
		case Step::VolumeType:
			{
				VolumeCreationIntroWizardPage *page = dynamic_cast <VolumeCreationIntroWizardPage *> (GetCurrentPage());
				SelectedVolumeType = page->GetSelection();
				
				if (forward && SelectedVolumeType != VolumeType::Normal)
				{
					Gui->ShowInfo ("FEATURE_CURRENTLY_UNSUPPORTED_ON_PLATFORM");
					return Step::VolumeType;
				}

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
					}
				}

				if (SelectedVolumePath.IsDevice())
					return Step::EncryptionOptions;
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

				return Step::EncryptionOptions;
			}

		case Step::EncryptionOptions:
			{
				EncryptionOptionsWizardPage *page = dynamic_cast <EncryptionOptionsWizardPage *> (GetCurrentPage());
				SelectedEncryptionAlgorithm = page->GetEncryptionAlgorithm ();
				SelectedHash = page->GetHash ();

				if (forward)
					RandomNumberGenerator::SetHash (SelectedHash);

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
						options->Type = SelectedVolumeType;
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
			return Step::VolumeType;

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
