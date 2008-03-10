#
# Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.
#
# Governed by the TrueCrypt License 2.4 the full text of which is contained
# in the file License.txt included in TrueCrypt binary and source code
# distribution packages.
#

OBJS :=
OBJS += Application.o
OBJS += CommandLineInterface.o
OBJS += FavoriteVolume.o
OBJS += FatalErrorHandler.o
OBJS += GraphicUserInterface.o
OBJS += LanguageStrings.o
OBJS += Hotkey.o
OBJS += StringFormatter.o
OBJS += TextUserInterface.o
OBJS += UserInterface.o
OBJS += UserPreferences.o
OBJS += VolumeHistory.o
OBJS += Xml.o
OBJS += Unix/Main.o
OBJS += Forms/AboutDialog.o
OBJS += Forms/ChangePasswordDialog.o
OBJS += Forms/DeviceSelectionDialog.o
OBJS += Forms/EncryptionOptionsWizardPage.o
OBJS += Forms/FavoriteVolumesDialog.o
OBJS += Forms/Forms.o
OBJS += Forms/InfoWizardPage.o
OBJS += Forms/KeyfilesDialog.o
OBJS += Forms/KeyfilesPanel.o
OBJS += Forms/LegalNoticesDialog.o
OBJS += Forms/MainFrame.o
OBJS += Forms/MountOptionsDialog.o
OBJS += Forms/PreferencesDialog.o
OBJS += Forms/ProgressWizardPage.o
OBJS += Forms/SelectDirectoryWizardPage.o
OBJS += Forms/SingleChoiceWizardPage.o
OBJS += Forms/VolumePasswordPanel.o
OBJS += Forms/VolumePropertiesDialog.o
OBJS += Forms/VolumeCreationIntroWizardPage.o
OBJS += Forms/VolumeCreationProgressWizardPage.o
OBJS += Forms/VolumeCreationWizard.o
OBJS += Forms/VolumeFormatOptionsWizardPage.o
OBJS += Forms/VolumeLocationWizardPage.o
OBJS += Forms/VolumePasswordWizardPage.o
OBJS += Forms/VolumeSizeWizardPage.o
OBJS += Forms/WizardFrame.o
OBJS += Resources.o

ifndef DISABLE_PRECOMPILED_HEADERS
PCH := SystemPrecompiled.h.gch
endif

RESOURCES :=
RESOURCES += ../License.txt.h
RESOURCES += ../Common/Language.xml.h
RESOURCES += ../Common/Textual_logo_96dpi.bmp.h
RESOURCES += ../Format/TrueCrypt_Wizard.bmp.h
RESOURCES += ../Mount/Drive_icon_96dpi.bmp.h
RESOURCES += ../Mount/Drive_icon_mask_96dpi.bmp.h
RESOURCES += ../Mount/Logo_96dpi.bmp.h

CXXFLAGS += -I$(BASE_DIR)/Main


#------ wxWidgets configuration ------

ifeq "$(TC_BUILD_CONFIG)" "Release"

CXXFLAGS += $(shell $(WX_BUILD_DIR)/wx-config --unicode --static --cxxflags)
WX_LIBS = $(shell $(WX_BUILD_DIR)/wx-config --unicode --static --libs adv,core,base)

else

CXXFLAGS += $(shell $(WX_BUILD_DIR)/wx-config --debug --unicode --static --cxxflags)
WX_LIBS = $(shell $(WX_BUILD_DIR)/wx-config --debug --unicode --static --libs adv,core,base)

endif


#------ FUSE configuration ------

FUSE_LIBS = $(shell pkg-config fuse --libs)


#------ Executable ------

TC_VERSION = $(shell grep VERSION_STRING ../Common/Tcdefs.h | head -n 1 | cut -d'"' -f 2)

$(APPNAME): $(LIBS) $(OBJS)
	@echo Linking $@
	$(CXX) -o $(APPNAME) $(LFLAGS) $(OBJS) $(LIBS) $(FUSE_LIBS) $(WX_LIBS)

ifeq "$(TC_BUILD_CONFIG)" "Release"
ifndef NOSTRIP
	strip $(APPNAME)
endif

ifndef NOTEST
	./$(APPNAME) --text --test >/dev/null
endif
endif

ifeq "$(PLATFORM)" "MacOSX"
	mkdir -p $(APPNAME).app/Contents/MacOS $(APPNAME).app/Contents/Resources
	-rm -f $(APPNAME).app/Contents/MacOS/$(APPNAME)
	
ifeq "$(TC_BUILD_CONFIG)" "Release"
	cp $(PWD)/Main/$(APPNAME) $(APPNAME).app/Contents/MacOS/$(APPNAME)
else
	-ln -sf $(PWD)/Main/$(APPNAME) $(APPNAME).app/Contents/MacOS/$(APPNAME)
endif

	cp $(PWD)/Resources/Icons/TrueCrypt.icns $(APPNAME).app/Contents/Resources
	
	echo -n APPLTRUE >$(APPNAME).app/Contents/PkgInfo
	sed -e 's/_VERSION_/$(patsubst %a,%.1,$(patsubst %b,%.2,$(TC_VERSION)))/' ../Build/Resources/MacOSX/Info.plist.xml >$(APPNAME).app/Contents/Info.plist
endif

$(OBJS): $(PCH)

Resources.o: $(RESOURCES)

include $(BUILD_INC)/Makefile.inc
