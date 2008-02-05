#ifndef TC_HEADER_Main_Forms_VolumePropertiesDialog
#define TC_HEADER_Main_Forms_VolumePropertiesDialog

#include "Forms.h"
#include "Main/Main.h"

namespace TrueCrypt
{
	class VolumePropertiesDialog : public VolumePropertiesDialogBase
	{
	public:
		VolumePropertiesDialog (wxWindow* parent, const VolumeInfo &volumeInfo);
		
		void AppendToList (const string &name, const wxString &value);
	};
}

#endif // TC_HEADER_Main_Forms_VolumePropertiesDialog
