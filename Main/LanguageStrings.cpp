/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "System.h"
#include "Resources.h"
#include "LanguageStrings.h"
#include "Xml.h"

namespace TrueCrypt
{
	LanguageStrings::LanguageStrings ()
	{
	}

	LanguageStrings::~LanguageStrings ()
	{
	}

	wxString LanguageStrings::operator[] (const string &key) const
	{
		if (Map.count (key) > 0)
			return wxString (Map.find (key)->second);

		return wxString (L"?") + StringConverter::ToWide (key) + L"?";
	}

	wstring LanguageStrings::Get (const string &key) const
	{
		return wstring (LangString[key]);
	}

	void LanguageStrings::Init ()
	{
		foreach (XmlNode node, XmlParser (Resources::GetLanguageXml()).GetNodes (L"string"))
		{
			wxString text = node.InnerText;
			text.Replace (L"\\n", L"\n");
			Map[StringConverter::ToSingle (wstring (node.Attributes[L"key"]))] = text;
		}

		Map["EXCEPTION_OCCURRED"] = _("Exception occurred");
		Map["MOUNT"] = _("Mount");
		Map["MOUNT_POINT"] = _("Mount Directory");
		Map["NO"] = _("No");
		Map["NO_VOLUMES_MOUNTED"] = _("No volumes mounted.");
		Map["OPEN_NEW_VOLUME"] = _("Specify a New TrueCrypt Volume");
		Map["PARAMETER_INCORRECT"] = _("Parameter incorrrect");
		Map["SELECT_KEYFILES"] = _("Select Keyfiles");
		Map["START_TC"] = _("Start TrueCrypt");
		Map["VOLUME_ALREADY_MOUNTED"] = _("The volume \"{0}\" is already mounted.");
		Map["UNKNOWN_OPTION"] = _("Unknown option");
		Map["VOLUME_LOCATION"] = _("Volume Location");
		Map["VOLUME_LOCATION_WIZARD_PAGE_INFO"] = _("You can create file-hosted volumes or encrypt entire hard disk partitions, floppy disks, USB memory sticks, and other storage devices. Click 'Select File...' to specify the name and path of the file to be created to host the new volume, or click 'Select Device...' to choose a partition or device to encrypt.\n\nWarning: If you encrypt a partition or a device, all data currently stored on the partition or the device will be erased.");
		Map["VOLUME_CREATION_WIZARD"] = _("TrueCrypt Volume Creation Wizard");
		Map["VOLUME_CREATION_INTRO"] = _("\nThis wizard will help you to create a new TrueCrypt volume.\n\nImportant: Collection of random data has begun. The data will be used in generating the master key, the secondary key (XTS mode), and salt, for the new volume. The collected data include your mouse movements within this window, keystrokes, and other data obtained from the system. The data should be as random as possible, so the more randomly and the longer you move the mouse, the better.");
		Map["YES"] = _("Yes");
		Map["VOLUME_HOST_IN_USE"] = _("WARNING: The host file/device \"{0}\" is already in use!\n\nIgnoring this can cause undesired results including system instability. All applications that might be using the host file/device should be closed before mounting the volume.\n\nContinue with mounting?");
		Map["VIRTUAL_DEVICE"] = _("Virtual Device");
		Map["FEATURE_CURRENTLY_UNSUPPORTED_ON_PLATFORM"] = _("The selected feature is currently not supported on your platform.");
		Map["CONFIRM_BACKGROUND_TASK_DISABLED"] = _("WARNING: If the TrueCrypt Background Task is disabled, the following functions, depending on the platform, will be disabled whenever you exit TrueCrypt:\n\n1) Auto-dismount (e.g., upon log off, time-out, etc.)\n2) Notifications (e.g., when damage to hidden volume is prevented)\n3) Tray icon\n\nNote: You may shut down the Background Task anytime by right-clicking the TrueCrypt tray icon and selecting 'Exit'.\n\nAre you sure you want to disable the TrueCrypt Background Task?");
		Map["CONFIRM_EXIT"] = _("WARNING: If TrueCrypt exits now, the following functions, depending on the platform, will be disabled:\n\n1) Auto-dismount (e.g., upon log off, time-out, etc.)\n2) Notifications (e.g., when damage to hidden volume is prevented)\n3) Tray icon\n\nNote: If you do not wish TrueCrypt to continue running in background after you close its window, disable the Background Task in the Preferences.\n\nAre you sure you want TrueCrypt to exit?");
		Map["DAMAGE_TO_HIDDEN_VOLUME_PREVENTED"] = _("WARNING: Data were attempted to be saved to the hidden volume area of the volume \"{0}\"!\n\nTrueCrypt prevented these data from being saved in order to protect the hidden volume. This may have caused filesystem corruption on the outer volume and the operating system may have reported a write error (\"Delayed Write Failed\", \"The parameter is incorrect\", etc.). The entire volume (both the outer and the hidden part) will be write-protected until it is dismounted.\n\nWe strongly recommend that you restart the operating system now.");
		Map["ENTER_PASSWORD"] = _("Enter password");
		Map["ENTER_PASSWORD_FOR"] = _("Enter password for \"{0}\"");
		Map["ENTER_TC_VOL_PASSWORD"] = _("Enter TrueCrypt Volume Password");
		Map["SELECT_KEYFILE_PATH"] = _("Select Keyfile Search Path");
		Map["HIDVOL_PROT_WARN_AFTER_MOUNT"] = _("The hidden volume is now protected against damage until the outer volume is dismounted.\n\nWARNING: If any data is attempted to be saved to the hidden volume area, TrueCrypt will start write-protecting the entire volume (both the outer and the hidden part) until it is dismounted. This may cause filesystem corruption on the outer volume. Any data being saved to the hidden volume area will NOT be saved and will be lost! The operating system may report this as a write error (\"Delayed Write Failed\", \"The parameter is incorrect\", etc.).");
		Map["HIDVOL_PROT_WARN_AFTER_MOUNT_PLURAL"] = _("Each of the hidden volumes within the newly mounted volumes is now protected against damage until dismounted.\n\nWARNING: If any data is attempted to be saved to protected hidden volume area of any of these volumes, TrueCrypt will start write-protecting the entire volume (both the outer and the hidden part) until it is dismounted. This may cause filesystem corruption on the outer volume. Any data being saved to protected hidden volume areas will NOT be saved and will be lost! The operating system may report this as a write error (\"Delayed Write Failed\", \"The parameter is incorrect\", etc.).");
		Map["MOUNTED_VOLUMES_AUTO_DISMOUNTED"] = _("TrueCrypt volumes have been auto-dismounted.\n\nNote: You can disable or configure auto-dismount in the Preferences (select Settings -> Preferences).");
		Map["MORE_INFO_ABOUT"] = _("More information on {0}");
		Map["IDPM_PROPERTIES"] = _("&Properties...");
		Map["TWO_LAYER_CASCADE_HELP"] = _("Two ciphers in a cascade operating in XTS mode. Each block is first encrypted with {0} ({1}-bit key) and then with {2} ({3}-bit key). Each cipher uses its own key. All keys are mutually independent.");
		Map["THREE_LAYER_CASCADE_HELP"] = _("Three ciphers in a cascade operating in XTS mode. Each block is first encrypted with {0} ({1}-bit key), then with {2} ({3}-bit key), and finally with {4} ({5}-bit key). Each cipher uses its own key. All keys are mutually independent.");
		Map["CHECKING_FS"] = _("Checking the file system on the TrueCrypt volume mounted as {0}...");
		Map["REPAIRING_FS"] = _("Attempting to repair the file system on the TrueCrypt volume mounted as {0}...");
		Map["TESTS_PASSED"] = _("Self-tests of all algorithms passed.");
		Map["UNMOUNT_LOCK_FAILED"] = _("Volume \"{0}\" contains files or folders being used by applications or system.\n\nForce dismount?");
		Map["VOLUME_SIZE_HELP"] = _("Please specify the size of the container to create.\n\nIf you create a dynamic (sparse-file) container, this parameter will specify its maximum size.\n\nNote that the minimum possible size of a FAT volume is 19 KB. The minimum possible size of an NTFS volume is 2573 KB.");
	}

	LanguageStrings LangString;
}
