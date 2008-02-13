/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <wx/mimetype.h>
#include <wx/sckipc.h>
#include "System.h"

#ifdef TC_UNIX
#include <signal.h>
#include <sys/utsname.h>
#include "Platform/Unix/Process.h"
#endif

#include "Application.h"
#include "GraphicUserInterface.h"
#include "FatalErrorHandler.h"
#include "Forms/DeviceSelectionDialog.h"
#include "Forms/MainFrame.h"
#include "Forms/MountOptionsDialog.h"

namespace TrueCrypt
{
	GraphicUserInterface::GraphicUserInterface () : BackgroundMode (false), mMainFrame (nullptr)
	{
#ifdef TC_UNIX
		signal (SIGHUP, OnSignal);
		signal (SIGINT, OnSignal);
		signal (SIGQUIT, OnSignal);
		signal (SIGTERM, OnSignal);
#endif

#ifdef TC_MACOSX
		wxApp::s_macHelpMenuTitleName = _("Help");
#endif
	}

	GraphicUserInterface::~GraphicUserInterface ()
	{
		FatalErrorHandler::Deregister();

#ifdef TC_UNIX
		signal (SIGHUP, SIG_DFL);
		signal (SIGINT, SIG_DFL);
		signal (SIGQUIT, SIG_DFL);
		signal (SIGTERM, SIG_DFL);
#endif
	}
	
	void GraphicUserInterface::AppendToListCtrl (wxListCtrl *listCtrl, const vector <wstring> &itemFields, int imageIndex, void *itemDataPtr) const
	{
		InsertToListCtrl (listCtrl, listCtrl->GetItemCount(), itemFields, imageIndex, itemDataPtr);
	}

	wxMenuItem *GraphicUserInterface::AppendToMenu (wxMenu &menu, const wxString &label, wxEvtHandler *handler, wxObjectEventFunction handlerFunction, int itemId) const
	{
		wxMenuItem *item = new wxMenuItem (&menu, itemId, label);
		menu.Append (item);
		
		if (handler)
			handler->Connect (item->GetId(), wxEVT_COMMAND_MENU_SELECTED, handlerFunction);

		return item;
	}

	bool GraphicUserInterface::AskYesNo (const wxString &message, bool defaultYes, bool warning) const
	{
		return ShowMessage (message,
			wxYES_NO | (warning ? wxICON_EXCLAMATION : wxICON_QUESTION) | (defaultYes ? wxYES_DEFAULT : wxNO_DEFAULT)
			) == wxYES;
	}

	void GraphicUserInterface::AutoDismountVolumes (VolumeInfoList mountedVolumes, bool alwaysForce)
	{
		size_t mountedVolumeCount = Core->GetMountedVolumes().size();
		try
		{
			wxBusyCursor busy;
			DismountVolumes (mountedVolumes, alwaysForce ? true : GetPreferences().ForceAutoDismount, false);
		}
		catch (...) { }

		if (Core->GetMountedVolumes().size() < mountedVolumeCount)
			OnVolumesAutoDismounted();
	}
	
	void GraphicUserInterface::BeginInteractiveBusyState (wxWindow *window)
	{
		static auto_ptr <wxCursor> arrowWaitCursor;

		if (arrowWaitCursor.get() == nullptr)
			arrowWaitCursor.reset (new wxCursor (wxCURSOR_ARROWWAIT));

		window->SetCursor (*arrowWaitCursor);
	}

	void GraphicUserInterface::ChangePassword (shared_ptr <VolumePath> volumePath, shared_ptr <VolumePassword> password, shared_ptr <KeyfileList> keyfiles, shared_ptr <VolumePassword> newPassword, shared_ptr <KeyfileList> newKeyfiles) const
	{
		Gui->ShowError (_("This feature is currently supported only in text mode."));
		throw UserAbort (SRC_POS);
	}

	void GraphicUserInterface::ClearListCtrlSelection (wxListCtrl *listCtrl) const
	{
		foreach (long item, GetListCtrlSelectedItems (listCtrl))
			listCtrl->SetItemState (item, 0, wxLIST_STATE_SELECTED);
	}

	void GraphicUserInterface::DoShowError (const wxString &message) const
	{
		ShowMessage (message, wxOK | wxICON_ERROR);
	}
	
	void GraphicUserInterface::DoShowInfo (const wxString &message) const
	{
		ShowMessage (message, wxOK | wxICON_INFORMATION);
	}

	void GraphicUserInterface::DoShowString (const wxString &str) const
	{
		ShowMessage (str, wxOK);
	}

	void GraphicUserInterface::DoShowWarning (const wxString &message) const
	{
		ShowMessage (message, wxOK 
#ifndef TC_MACOSX
			| wxICON_EXCLAMATION
#endif
			);
	}
	
	void GraphicUserInterface::EndInteractiveBusyState (wxWindow *window) const
	{
		static auto_ptr <wxCursor> arrowCursor;

		if (arrowCursor.get() == nullptr)
			arrowCursor.reset (new wxCursor (wxCURSOR_ARROW));

		window->SetCursor (*arrowCursor);
	}

	wxTopLevelWindow *GraphicUserInterface::GetActiveWindow () const
	{
#ifdef TC_WINDOWS
		return dynamic_cast <wxTopLevelWindow *> (wxGetActiveWindow());
#endif
		if (wxTopLevelWindows.size() == 1)
			return dynamic_cast <wxTopLevelWindow *> (wxTopLevelWindows.front());

#ifdef __WXGTK__
		wxLongLong startTime = wxGetLocalTimeMillis();
		do
		{
#endif
			foreach (wxWindow *window, wxTopLevelWindows)
			{
				wxTopLevelWindow *topLevelWin = dynamic_cast <wxTopLevelWindow *> (window);
				if (topLevelWin && topLevelWin->IsActive() && topLevelWin->IsShown())
					return topLevelWin;
			}
#ifdef __WXGTK__
			Yield(); // GTK does a lot of operations asynchronously, which makes it prone to many race conditions
		} while	(wxGetLocalTimeMillis() - startTime < 500);
#endif

		return dynamic_cast <wxTopLevelWindow *> (GetTopWindow());
	}

	shared_ptr <GetStringFunctor> GraphicUserInterface::GetAdminPasswordRequestHandler ()
	{
		struct AdminPasswordRequestHandler : public GetStringFunctor
		{
			virtual string operator() ()
			{
				wxPasswordEntryDialog dialog (Gui->GetActiveWindow(), LangString["ENTER_PASSWORD"] + L":", _("Administrator privileges required"));

				if (dialog.ShowModal() != wxID_OK)
					throw UserAbort (SRC_POS);

				return StringConverter::ToSingle (wstring (dialog.GetValue()));
			}
		};

		return shared_ptr <GetStringFunctor> (new AdminPasswordRequestHandler);
	}
	
	int GraphicUserInterface::GetCharHeight (wxWindow *window) const
	{
		int width;
		int height;
		window->GetTextExtent (L"a", &width, &height);

		if (height < 1)
			return 14;

		return height;
	}

	int GraphicUserInterface::GetCharWidth (wxWindow *window) const
	{
		int width;
		int height;
		window->GetTextExtent (L"a", &width, &height);

		if (width < 1)
			return 7;

		return width;
	}

	wxFont GraphicUserInterface::GetDefaultBoldFont (wxWindow *window) const
	{
		return wxFont (
#ifdef __WXGTK__
			9
#elif defined(TC_MACOSX)
			13
#else
			10 
#endif
			* GetCharHeight (window) / 13, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, 
#ifdef __WXGTK__
			wxFONTWEIGHT_BOLD, false);
#elif defined(TC_MACOSX)
			wxFONTWEIGHT_NORMAL, false);
#else
			wxFONTWEIGHT_BOLD, false, L"Arial");
#endif
	}

	list <long> GraphicUserInterface::GetListCtrlSelectedItems (wxListCtrl *listCtrl) const
	{
		list <long> selectedItems;
		
		long item = -1;
		while ((item = listCtrl->GetNextItem (item, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED)) != -1)
			selectedItems.push_back (item);

		return selectedItems;
	}

	wxString GraphicUserInterface::GetListCtrlSubItemText (wxListCtrl *listCtrl, long itemIndex, int columnIndex) const
	{
		wxListItem item;
		item.SetId (itemIndex);
		item.SetColumn (columnIndex);
		item.SetText (L"");
			
		if (!listCtrl->GetItem (item))
			throw ParameterIncorrect (SRC_POS);

		return item.GetText();
	}

	int GraphicUserInterface::GetScrollbarWidth (wxWindow *window, bool noScrollBar) const
	{
		int offset = 0;
#ifdef TC_WINDOWS
		offset = 4;
#elif defined (__WXGTK__)
		offset = 5;
#elif defined (TC_MACOSX)
		offset = 9;
#endif
		if (noScrollBar)
			return offset;

		int width = wxSystemSettings::GetMetric (wxSYS_VSCROLL_X, window);
		if (width == -1)
			return 24;

		return width + offset;
	}


	void GraphicUserInterface::InsertToListCtrl (wxListCtrl *listCtrl, long itemIndex, const vector <wstring> &itemFields, int imageIndex, void *itemDataPtr) const
	{
		wxListItem item;
		item.SetData (itemDataPtr);
		item.SetId (itemIndex);
		item.SetImage (imageIndex);
		int col = 0;
		foreach (wxString field, itemFields)
		{
			item.SetColumn (col++);
			item.SetText (field);
			if (col == 1)
			{
				throw_sys_if (listCtrl->InsertItem (item) == -1);
				item.SetImage (-1);
				continue;
			}

			listCtrl->SetItem (item);
		}
	}
	
	bool GraphicUserInterface::IsTheOnlyTopLevelWindow (const wxWindow *window) const
	{
		foreach (wxWindow *w, wxTopLevelWindows)
		{
			if (w != window
				&& (dynamic_cast <const wxFrame *> (w) || dynamic_cast <const wxDialog *> (w))
				&& StringConverter::GetTypeName (typeid (*w)).find ("wxTaskBarIcon") == string::npos)
			{
				return false;
			}
		}
		return true;
	}

	void GraphicUserInterface::MoveListCtrlItem (wxListCtrl *listCtrl, long itemIndex, long newItemIndex) const
	{
		if (itemIndex == newItemIndex || newItemIndex < 0
			|| (newItemIndex > itemIndex && newItemIndex == listCtrl->GetItemCount()))
			return;

		wxListItem item;
		item.SetId (itemIndex);
		item.SetData ((void *) nullptr);
		item.SetImage (-1);
		
		if (!listCtrl->GetItem (item))
			throw ParameterIncorrect (SRC_POS);

		int itemState = listCtrl->GetItemState (itemIndex, wxLIST_STATE_SELECTED);

		vector <wstring> itemFields (listCtrl->GetColumnCount());
		for (size_t col = 0; col < itemFields.size(); ++col)
		{
			itemFields[col] = GetListCtrlSubItemText (listCtrl, itemIndex, col);
		}

		listCtrl->DeleteItem (itemIndex);
		
		if (newItemIndex > listCtrl->GetItemCount() - 1)
			AppendToListCtrl (listCtrl, itemFields, item.GetImage(), (void *) item.GetData());
		else
			InsertToListCtrl (listCtrl, newItemIndex, itemFields, item.GetImage(), (void *) item.GetData());

		item.SetId (newItemIndex);
		listCtrl->SetItemState (item, itemState, wxLIST_STATE_SELECTED);
	}

	VolumeInfoList GraphicUserInterface::MountAllDeviceHostedVolumes (MountOptions &options) const
	{
		MountOptionsDialog dialog (GetTopWindow(), options);
		while (true)
		{
			options.Path.reset();

			if (dialog.ShowModal() != wxID_OK)
				return VolumeInfoList();

			VolumeInfoList mountedVolumes = UserInterface::MountAllDeviceHostedVolumes (options);
			
			if (!mountedVolumes.empty())
				return mountedVolumes;
		}
	}

	shared_ptr <VolumeInfo> GraphicUserInterface::MountVolume (MountOptions &options) const
	{
		shared_ptr <VolumeInfo> volume;

		if (Core->IsVolumeMounted (*options.Path))
		{
			ShowInfo (StringFormatter (LangString["VOLUME_ALREADY_MOUNTED"], wstring (*options.Path)));
			return volume;
		}

		try
		{
			if ((!options.Password || options.Password->IsEmpty())
				&& (!options.Keyfiles || options.Keyfiles->empty())
				&& !Core->IsPasswordCacheEmpty())
			{
				// Cached password
				try
				{
					wxBusyCursor busy;
					return UserInterface::MountVolume (options);
				}
				catch (PasswordException&) { }
			}

			VolumePassword password;
			KeyfileList keyfiles;

			MountOptionsDialog dialog (GetTopWindow(), options);
			while (!volume)
			{
				dialog.Hide();
				if (dialog.ShowModal() != wxID_OK)
					return volume;

				try
				{
					wxBusyCursor busy;
					volume = UserInterface::MountVolume (options);
				}
				catch (PasswordException &e)
				{
					ShowWarning (e);
				}
			}
		}
		catch (exception &e)
		{
			ShowError (e);
		}

		return volume;
	}

	void GraphicUserInterface::OnAutoDismountAllEvent ()
	{
		VolumeInfoList mountedVolumes = Core->GetMountedVolumes();

		if (!mountedVolumes.empty())
		{
			wxBusyCursor busy;
			AutoDismountVolumes (mountedVolumes);
		}
	}

	bool GraphicUserInterface::OnInit ()
	{
		Gui = this;
		InterfaceType = UserInterfaceType::Graphic;
		try
		{
			FatalErrorHandler::Register();
			Init();

			if (ProcessCommandLine() && !CmdLine->StartBackgroundTask)
			{
				Yield();
				Application::SetExitCode (0);
				return false;
			}

			// Check if another instance is already running and bring its windows to foreground
#ifndef TC_MACOSX
#ifdef TC_WINDOWS
			const wxString serverName = Application::GetName() + L"-" + wxGetUserId();
			class Connection : public wxDDEConnection
			{
			public:
				Connection () { }

				bool OnExecute (const wxString& topic, wxChar *data, int size, wxIPCFormat format)
				{
					if (topic == L"raise")
					{
						if (Gui->IsInBackgroundMode())
							Gui->SetBackgroundMode (false);

						Gui->mMainFrame->Show (true);
						Gui->mMainFrame->Raise ();
						return true;
					}
					return false;
				}
			};
#endif

			SingleInstanceChecker.reset (new wxSingleInstanceChecker (wxString (L".") + Application::GetName() + L"-lock-" + wxGetUserId()));
			
			if (SingleInstanceChecker->IsAnotherRunning())
			{
#ifdef TC_WINDOWS
				class Client: public wxDDEClient
				{
				public:
					Client() {};
					wxConnectionBase *OnMakeConnection () { return new Connection; }
				};

				auto_ptr <wxDDEClient> client (new Client);
				auto_ptr <wxConnectionBase> connection (client->MakeConnection (L"localhost", serverName, L"raise"));

				if (connection.get() && connection->Execute (nullptr))
				{
					connection->Disconnect();
					Application::SetExitCode (0);
					return false;
				}
#endif
				wxLog::FlushActive();
				Application::SetExitCode (1);
				Gui->ShowInfo (_("TrueCrypt is already running."));
				return false;
			}

#ifdef TC_WINDOWS
			class Server : public wxDDEServer
			{
			public:
				wxConnectionBase *OnAcceptConnection (const wxString &topic)
				{
					if (topic == L"raise")
						return new Connection;
					return nullptr;
				}
			};

			DDEServer.reset (new Server);
			if (!DDEServer->Create (serverName))
				wxLog::FlushActive();
#endif
#endif // !TC_MACOSX

			Connect (wxEVT_END_SESSION, wxCloseEventHandler (GraphicUserInterface::OnEndSession));
#ifdef wxHAS_POWER_EVENTS
			Gui->Connect (wxEVT_POWER_SUSPENDING, wxPowerEventHandler (GraphicUserInterface::OnPowerSuspending));
#endif

			mMainFrame = new MainFrame (nullptr);

			if (CmdLine->StartBackgroundTask)
			{
				UserPreferences prefs = GetPreferences ();
				prefs.BackgroundTaskEnabled = true;
				SetPreferences (prefs);
				mMainFrame->Close();
			}
			else
			{
				mMainFrame->Show (true);
			}

			SetTopWindow (mMainFrame);
		}
		catch (exception &e)
		{
			ShowError (e);
			return false;
		}

		return true;
	}
	
	void GraphicUserInterface::OnLogOff ()
	{
		VolumeInfoList mountedVolumes = Core->GetMountedVolumes();
		if (GetPreferences().BackgroundTaskEnabled && GetPreferences().DismountOnLogOff
			&& !mountedVolumes.empty())
		{
			wxLongLong startTime = wxGetLocalTimeMillis();
			bool timeOver = false;

			wxBusyCursor busy;
			while (!timeOver && !mountedVolumes.empty())
			{
				try
				{
					timeOver = (wxGetLocalTimeMillis() - startTime >= 4000);
					
					DismountVolumes (mountedVolumes, !timeOver ? false : GetPreferences().ForceAutoDismount, timeOver);
					OnVolumesAutoDismounted();
					
					break;
				}
				catch (UserAbort&)
				{
					return;
				}
				catch (...)
				{
					Thread::Sleep (500);
				}

				VolumeInfoList mountedVolumes = Core->GetMountedVolumes();
			}

		}
	}

#ifdef wxHAS_POWER_EVENTS
	void GraphicUserInterface::OnPowerSuspending (wxPowerEvent& event)
	{
		size_t volumeCount = Core->GetMountedVolumes().size();
		if (GetPreferences().BackgroundTaskEnabled && GetPreferences().DismountOnPowerSaving && volumeCount > 0)
		{
			OnAutoDismountAllEvent();

			if (Core->GetMountedVolumes().size() < volumeCount)
				ShowInfoTopMost (LangString["MOUNTED_VOLUMES_AUTO_DISMOUNTED"]);
		}
	}
#endif

	void GraphicUserInterface::OnSignal (int signal)
	{
#ifdef TC_UNIX
		Gui->SingleInstanceChecker.reset();
		_exit (1);
#endif
	}

	void GraphicUserInterface::OnVolumesAutoDismounted ()
	{
		if (GetPreferences().WipeCacheOnAutoDismount)
			Core->WipePasswordCache();
	}

	void GraphicUserInterface::OpenDocument (wxWindow *parent, const wxFileName &document)
	{

#ifdef TC_WINDOWS

		if (int (ShellExecute (GetTopWindow() ? static_cast <HWND> (GetTopWindow()->GetHandle()) : nullptr, L"open",
		document.GetFullPath().c_str(), nullptr, nullptr, SW_SHOWNORMAL)) >= 32)
		return;

#else
		wxMimeTypesManager mimeMgr;
		wxFileType *fileType = mimeMgr.GetFileTypeFromExtension (document.GetExt());
		if (fileType)
		{
			try
			{
#ifdef TC_MACOSX
				if (wxExecute (fileType->GetOpenCommand (document.GetFullPath())) != 0)
					return;
#else
				if (wxExecute (fileType->GetOpenCommand (L"\"" + document.GetFullPath() + L"\"")) != 0)
					return;
#endif
			}
			catch (TimeOut&)
			{
				return;
			}
			catch (Exception &e)
			{
				Gui->ShowError (e);
			}
		}
#endif
		if (Gui->AskYesNo (LangString ["HELP_READER_ERROR"]))
			OpenOnlineHelp (parent);
	}

	wxString GraphicUserInterface::GetHomepageLinkURL (const wxString &linkId, const wxString &extraVars) const
	{
		wxString url = wxString (L"http://www.truecrypt.org/applink.php?version=") + StringConverter::ToWide (Version::String()) + L"&dest=" + linkId;
		
		wxString os, osVersion, architecture;

#ifdef TC_WINDOWS

		os = L"Windows";

#elif defined (TC_UNIX)
		struct utsname unameData;
		if (uname (&unameData) != -1)
		{
			os = StringConverter::ToWide (unameData.sysname);
			osVersion = StringConverter::ToWide (unameData.release);
			architecture = StringConverter::ToWide (unameData.machine);
			//os = L"MacOSX";

			if (os == L"Darwin")
				os = L"MacOSX";
		}
		else
			os = L"Unknown";
#else
		os = L"Unknown";
#endif

		os.Replace (L" ", L"-");
		url += L"&os=";
		url += os;

		osVersion.Replace (L" ", L"-");
		url += L"&osver=";
		url += osVersion;

		architecture.Replace (L" ", L"-");
		url += L"&arch=";
		url += architecture;

		if (!extraVars.empty())
		{
			 url += L"&";
			 url += extraVars;
		}

		return url;
	}

	void GraphicUserInterface::OpenHomepageLink (wxWindow *parent, const wxString &linkId, const wxString &extraVars)
	{
		wxString url;
		
		BeginInteractiveBusyState (parent);
		wxLaunchDefaultBrowser (GetHomepageLinkURL (linkId, extraVars), wxBROWSER_NEW_WINDOW);
		Thread::Sleep (200);
		EndInteractiveBusyState (parent);
	}

	void GraphicUserInterface::OpenOnlineHelp (wxWindow *parent)
	{
		OpenHomepageLink (parent, L"help");
	}

	void GraphicUserInterface::OpenUserGuide (wxWindow *parent)
	{
		try
		{
			wxString docPath = wstring (Application::GetExecutableDirectory());

#ifdef TC_WINDOWS
			docPath += L"\\TrueCrypt User Guide.pdf";
#elif defined (TC_MACOSX)
			docPath += L"/../Resources/TrueCrypt User Guide.pdf";
#elif defined (TC_UNIX)
			docPath = L"/usr/share/truecrypt/doc/TrueCrypt User Guide.pdf";
#endif

			wxFileName docFile = docPath;
			docFile.Normalize();
			Gui->OpenDocument (parent, docFile);
		}
		catch (Exception &e)
		{
			Gui->ShowError (e);
		}
	}

	DevicePath GraphicUserInterface::SelectDevice (wxWindow *parent) const
	{
		try
		{
			DeviceSelectionDialog dialog (parent);
			if (dialog.ShowModal() == wxID_OK)
			{
				return dialog.SelectedDevice.Path;
			}
		}
		catch (exception &e)
		{
			Gui->ShowError (e);
		}

		return DevicePath();
	}

	DirectoryPath GraphicUserInterface::SelectDirectory (wxWindow *parent, const wxString &message, bool existingOnly) const
	{
		return DirectoryPath (::wxDirSelector (!message.empty() ? message :
#ifdef __WXGTK__
			wxDirSelectorPromptStr,
#else
			L"",
#endif
			L"", wxDD_DEFAULT_STYLE | (existingOnly ? wxDD_DIR_MUST_EXIST : 0), wxDefaultPosition, parent));
	}

	FilePathList GraphicUserInterface::SelectFiles (wxWindow *parent, const wxString &caption, bool saveMode, bool allowMultiple, const list < pair <wstring, wstring> > &fileExtensions, const DirectoryPath &directory) const
	{
		FilePathList files;

		long style;
		if (saveMode)
			style = wxFD_SAVE | wxFD_OVERWRITE_PROMPT;
		else
			style = wxFD_OPEN | wxFD_FILE_MUST_EXIST | (allowMultiple ? wxFD_MULTIPLE : 0);

		wxString wildcards = L"*.*";

#ifndef __WXGTK__
		if (!fileExtensions.empty())
#endif
		{
			wildcards = LangString["ALL_FILES"] + 
#ifdef TC_WINDOWS
				L" (*.*)|*.*";
#else
				L"|*";
#endif
			typedef pair <wstring, wstring> StringPair;
			foreach (StringPair p, fileExtensions)
			{
				wildcards += wxString (L"|") + p.second + L" (*." + p.first + L")|*." + p.first;
			}
		}

		wxFileDialog dialog (parent, caption, wstring (directory), wxString(), wildcards, style);

		if (dialog.ShowModal() == wxID_OK)
		{
			if (!allowMultiple)
				files.push_back (make_shared <FilePath> (dialog.GetPath()));
			else
			{
				wxArrayString paths;
				dialog.GetPaths (paths);

				foreach (const wxString &path, paths)
					files.push_back (make_shared <FilePath> (path));
			}
		}

		return files;
	}
	
	FilePath GraphicUserInterface::SelectVolumeFile (wxWindow *parent, bool saveMode, const DirectoryPath &directory) const
	{
		list < pair <wstring, wstring> > extensions;
		extensions.push_back (make_pair (L"tc", LangString["TC_VOLUMES"]));

		FilePathList selFiles = Gui->SelectFiles (parent, LangString[saveMode ? "OPEN_NEW_VOLUME" : "OPEN_VOL_TITLE"], saveMode, false, extensions, directory);

		if (!selFiles.empty())
			return *selFiles.front();
		else
			return FilePath();
	}

	void GraphicUserInterface::SetBackgroundMode (bool state)
	{
#ifdef TC_MACOSX
		// Hiding an iconized window on OS X apparently cannot be reversed
		if (state && mMainFrame->IsIconized())
			mMainFrame->Iconize (false);
#endif
		mMainFrame->Show (!state);
		if (!state)
		{
			if (mMainFrame->IsIconized())
				mMainFrame->Iconize (false);

			mMainFrame->Raise();
		}

		BackgroundMode = state;
	}

	void GraphicUserInterface::SetListCtrlColumnWidths (wxListCtrl *listCtrl, list <int> columnWidthPermilles, bool hasVerticalScrollbar) const
	{
#ifdef TC_MACOSX
		hasVerticalScrollbar = true;
#endif
		int listWidth = listCtrl->GetSize().GetWidth();
		int minListWidth = listCtrl->GetMinSize().GetWidth();
		if (minListWidth > listWidth)
			listWidth = minListWidth;

		listWidth -= GetScrollbarWidth (listCtrl, !hasVerticalScrollbar);
		
		int col = 0;
		int totalColWidth = 0;
		foreach (int colWidth, columnWidthPermilles)
		{
			int width = listWidth * colWidth / 1000;
			totalColWidth += width;
			
			if (col == listCtrl->GetColumnCount() - 1)
				width += listWidth - totalColWidth;

			listCtrl->SetColumnWidth (col++, width);
		}
	}

	void GraphicUserInterface::SetListCtrlHeight (wxListCtrl *listCtrl, size_t rowCount) const
	{
		wxRect itemRect;
		if (listCtrl->GetItemCount() == 0)
		{
			bool addedCols = false;
			if (listCtrl->GetColumnCount() == 0)
			{
				listCtrl->InsertColumn (0, L".", wxLIST_FORMAT_LEFT, 1);
				addedCols = true;
			}
			vector <wstring> f;
			f.push_back (L".");
			AppendToListCtrl (listCtrl, f);
			listCtrl->GetItemRect (0, itemRect);

			if (addedCols)
				listCtrl->ClearAll();
			else
				listCtrl->DeleteAllItems();
		}
		else
			listCtrl->GetItemRect (0, itemRect);

		int headerHeight = itemRect.y;
#ifdef TC_WINDOWS
		headerHeight += 4;
#elif defined (TC_MACOSX)
		headerHeight += 7;
#elif defined (__WXGTK__)
		headerHeight += 5;
#endif
		int rowHeight = itemRect.height;
#ifdef TC_MACOSX
		rowHeight += 1;
#endif
		listCtrl->SetMinSize (wxSize (listCtrl->GetMinSize().GetWidth(), rowHeight * rowCount + headerHeight));
	}

	void GraphicUserInterface::SetListCtrlWidth (wxListCtrl *listCtrl, size_t charCount, bool hasVerticalScrollbar) const
	{
		int width = GetCharWidth (listCtrl) * charCount;
#ifdef TC_MACOSX
		if (!hasVerticalScrollbar)
			width += GetScrollbarWidth (listCtrl);
#endif
		listCtrl->SetMinSize (wxSize (width, listCtrl->GetMinSize().GetHeight()));
	}

	void GraphicUserInterface::ShowErrorTopMost (const wxString &message) const
	{
		ShowMessage (message, wxOK | wxICON_ERROR, true);
	}

	void GraphicUserInterface::ShowInfoTopMost (const wxString &message) const
	{
		ShowMessage (message, wxOK | wxICON_INFORMATION, true);
	}
	
	int GraphicUserInterface::ShowMessage (const wxString &message, long style, bool topMost) const
	{
		wxString caption = Application::GetName();
		wxString subMessage = message;

#ifdef TC_MACOSX
		size_t p = message.find (L"\n");
		if (p != string::npos)
		{
			// Divide message to caption and info message
			caption = message.substr (0, p);

			p = message.find_first_not_of (L'\n', p);
			if (p != string::npos)
				subMessage = message.substr (p);
			else
				subMessage.clear();

			if (subMessage.EndsWith (L"?"))
			{
				// Move question to caption
				caption += wstring (L" ");
				p = subMessage.find_last_of (L".\n");
				if (p != string::npos)
				{
					if (caption.EndsWith (L": "))
						caption[caption.size() - 2] = L'.';

					caption += subMessage.substr (subMessage.find_first_not_of (L"\n ", p + 1));
					subMessage = subMessage.substr (0, p + 1);
				}
				else
				{
					caption += subMessage.substr (subMessage.find_first_not_of (L"\n"));
					subMessage.clear();
				}
			}
		}
		else if (message.size() < 160)
		{
			caption = message;
			subMessage.clear();
		}
		else
		{
			if (style & wxICON_EXCLAMATION)
				caption = wxString (_("Warning")) + L':';
			else if (style & wxICON_ERROR || style & wxICON_HAND)
				caption = wxString (_("Error")) + L':';
			else
				caption.clear();
		}
#endif
		if (topMost)
		{
			if (!IsActive())
				mMainFrame->RequestUserAttention (wxUSER_ATTENTION_ERROR);

			style |= wxSTAY_ON_TOP;
		}

		return wxMessageBox (subMessage, caption, style, GetActiveWindow());
	}

	void GraphicUserInterface::ShowWarningTopMost (const wxString &message) const
	{
		ShowMessage (message, wxOK 
#ifndef TC_MACOSX
			| wxICON_EXCLAMATION
#endif
			, true);
	}

	bool GraphicUserInterface::UpdateListCtrlItem (wxListCtrl *listCtrl, long itemIndex, const vector <wstring> &itemFields) const
	{
		bool changed = false;
		wxListItem item;
		item.SetId (itemIndex);
		item.SetText (L"");

		int col = 0;
		foreach (wxString field, itemFields)
		{
			item.SetColumn (col++);
			
			if (!listCtrl->GetItem (item))
				throw ParameterIncorrect (SRC_POS);

			if (item.GetText() != field)
			{
				item.SetText (field);
				listCtrl->SetItem (item);
				changed = true;
			}
		}
		return changed;
	}

	void GraphicUserInterface::Yield () const
	{
#ifndef TC_WINDOWS
		wxSafeYield (nullptr, true);
#endif
	}

	DEFINE_EVENT_TYPE (TC_EVENT_THREAD_EXITING);

	GraphicUserInterface *Gui = nullptr;
}
