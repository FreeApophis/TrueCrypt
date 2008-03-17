#
# Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.
#
# Governed by the TrueCrypt License 2.4 the full text of which is contained
# in the file License.txt included in TrueCrypt binary and source code
# distribution packages.
#

#------ Command line arguments ------
# DEBUG:		Disable optimizations and enable debug checks
# DEBUGGER:		Enable debugging information for use by debuggers
# NOGUI:		Disable graphical user interface (build console-only application)
# NOSTRIP:		Do not strip release binary
# NOTEST:		Do not test release binary
# VERBOSE:		Enable verbose messages

#------ Targets ------
# all
# clean
# wxbuild:		Configure and build wxWidgets - source code must be located at $(WX_ROOT)


export APPNAME := truecrypt
export BASE_DIR := $(CURDIR)
export BUILD_INC := $(BASE_DIR)/Build/Include

export TC_BUILD_CONFIG := Release

ifeq "$(origin DEBUG)" "command line"
ifneq "$(DEBUG)" "0"
TC_BUILD_CONFIG := Debug
endif
endif


#------ Build configuration ------

export AR ?= ar
export CC ?= gcc
export CXX ?= g++
export RANLIB ?= ranlib

export CFLAGS := -W
export CXXFLAGS := -Wall

C_CXX_FLAGS := -MMD -I$(BASE_DIR) -I$(BASE_DIR)/Crypto
C_CXX_FLAGS += -DBOOL=int -DFALSE=0 -DTRUE=1
C_CXX_FLAGS += -D__int8=char -D__int16=short -D__int32=int '-D__int64=long long'  # Tested in PlatformTest

export LFLAGS :=
export PKG_CONFIG_PATH ?= /usr/local/lib/pkgconfig

WX_CONFIGURE_FLAGS :=
export WXCONFIG_CFLAGS :=
export WXCONFIG_CXXFLAGS :=
WX_ROOT ?= ..

ifneq "$(origin VERBOSE)" "command line"
MAKEFLAGS += -s
endif

ifeq "$(origin NOGUI)" "command line"
export TC_NO_GUI := 1
C_CXX_FLAGS += -DTC_NO_GUI
WX_CONFIGURE_FLAGS += --disable-gui
endif


#------ Release configuration ------

ifeq "$(TC_BUILD_CONFIG)" "Release"

C_CXX_FLAGS += -O2 -fno-strict-aliasing  # Do not enable strict aliasing
CXXFLAGS += -Wno-sign-compare -Wno-unused-parameter
export WX_BUILD_DIR ?= $(BASE_DIR)/wxrelease
WX_CONFIGURE_FLAGS += --disable-debug_flag --disable-debug_gdb --disable-debug_info

else

#------ Debug configuration ------

C_CXX_FLAGS += -DDEBUG
CXXFLAGS += -fno-default-inline -Wno-sign-compare -Wno-unused-parameter -Wno-unused-function -Wno-unused-variable
export WX_BUILD_DIR ?= $(BASE_DIR)/wxdebug
WX_CONFIGURE_FLAGS += --enable-debug_flag --disable-debug_gdb --disable-debug_info

endif


#------ Debugger configuration ------

ifeq "$(origin DEBUGGER)" "command line"

C_CXX_FLAGS += -ggdb  
WX_CONFIGURE_FLAGS += --enable-debug_gdb --enable-debug_info

endif


#------ Platform configuration ------

export PLATFORM


#------ Linux configuration ------

ifeq "$(shell uname -s)" "Linux"

PLATFORM := Linux
C_CXX_FLAGS += -DTC_UNIX -DTC_LINUX

ifeq "$(TC_BUILD_CONFIG)" "Release"
C_CXX_FLAGS += -fdata-sections -ffunction-sections
LFLAGS += -Wl,--gc-sections

ifneq "$(shell ld --help 2>&1 | grep sysv | wc -l)" "0"
LFLAGS += -Wl,--hash-style=sysv
endif

WXCONFIG_CFLAGS += -fdata-sections -ffunction-sections
WXCONFIG_CXXFLAGS += -fdata-sections -ffunction-sections
endif

endif


#------ Mac OS X configuration ------

ifeq "$(shell uname -s)" "Darwin"

PLATFORM := MacOSX
APPNAME := TrueCrypt
C_CXX_FLAGS += -DTC_UNIX -DTC_BSD -DTC_MACOSX

ifeq "$(TC_BUILD_CONFIG)" "Release"

SDK ?= /Developer/SDKs/MacOSX10.4u.sdk
export DISABLE_PRECOMPILED_HEADERS := 1
S := $(C_CXX_FLAGS)
C_CXX_FLAGS = $(subst -MMD,,$(S))

C_CXX_FLAGS += -gfull -arch i386 -arch ppc -isysroot $(SDK)
LFLAGS += -Wl,-dead_strip -arch i386 -arch ppc -Wl,-syslibroot $(SDK)
WX_CONFIGURE_FLAGS += --enable-universal_binary
WXCONFIG_CFLAGS += -gfull
WXCONFIG_CXXFLAGS += -gfull

endif

endif


#------ FreeBSD configuration ------

ifeq "$(shell uname -s)" "FreeBSD"

PLATFORM := FreeBSD
C_CXX_FLAGS += -DTC_UNIX -DTC_BSD -DTC_FREEBSD

endif


#------ Common configuration ------

CFLAGS := $(C_CXX_FLAGS) $(CFLAGS) $(EXTRA_CFLAGS)
CXXFLAGS := $(C_CXX_FLAGS) $(CXXFLAGS) $(EXTRA_CXXFLAGS)
LFLAGS := $(LFLAGS) $(EXTRA_LFLAGS)

WX_CONFIGURE_FLAGS += --enable-unicode -disable-shared --disable-dependency-tracking --disable-compat26 --enable-exceptions --enable-std_string --enable-dataobj --enable-mimetype \
	--disable-protocol --disable-protocols --disable-url --disable-ipc --disable-sockets --disable-fs_inet --disable-ole --disable-docview --disable-clipboard \
	--disable-help --disable-html --disable-mshtmlhelp --disable-htmlhelp --disable-mdi --disable-metafile --disable-webkit \
	--disable-xrc --disable-aui --disable-postscript --disable-printarch \
	--disable-arcstream --disable-fs_archive --disable-fs_zip --disable-tarstream --disable-zipstream \
	--disable-animatectrl --disable-bmpcombobox --disable-calendar --disable-caret --disable-checklst --disable-collpane --disable-colourpicker --disable-comboctrl \
	--disable-datepick --disable-display --disable-dirpicker --disable-filepicker --disable-fontpicker --disable-grid  --disable-dataviewctrl \
	--disable-listbook --disable-odcombobox --disable-sash  --disable-searchctrl --disable-slider --disable-splitter --disable-togglebtn \
	--disable-toolbar --disable-tbarnative --disable-treebook --disable-toolbook --disable-tipwindow --disable-popupwin \
	--disable-commondlg --disable-aboutdlg --disable-coldlg --disable-finddlg --disable-fontdlg --disable-numberdlg --disable-splash \
	--disable-tipdlg --disable-progressdlg --disable-wizarddlg --disable-miniframe --disable-tooltips --disable-splines --disable-palette \
	--disable-richtext --disable-dialupman --disable-debugreport --disable-filesystem \
	--disable-graphics_ctx --disable-sound --disable-mediactrl --disable-joystick --disable-apple_ieee \
	--disable-gif --disable-pcx --disable-tga --disable-iff --disable-gif --disable-pnm \
	--without-expat --without-libtiff --without-libjpeg --without-libpng -without-regex --without-zlib


#------ Project build ------

PROJ_DIRS := Platform Volume Driver/Fuse Core Main

.PHONY: all clean wxbuild

all clean:
	@for DIR in $(PROJ_DIRS); do \
		PROJ=$$(echo $$DIR | cut -d/ -f1); \
		$(MAKE) -C $$DIR -f $$PROJ.make NAME=$$PROJ $(MAKECMDGOALS) || exit $?; \
		export LIBS="$(BASE_DIR)/$$DIR/$$PROJ.a $$LIBS"; \
	done	


#------ wxWidgets build ------

ifeq "$(MAKECMDGOALS)" "wxbuild"
CFLAGS :=
CXXFLAGS :=
LFLAGS :=
endif

wxbuild:

ifneq "$(shell test -f $(WX_ROOT)/configure || test -f $(WX_BUILD_DIR)/../configure && echo 1)" "1"
	@echo WX_ROOT must point to wxWidgets source code directory
	@exit 1
endif

	mkdir -p $(WX_BUILD_DIR)
	@echo Configuring wxWidgets library...
	cd $(WX_BUILD_DIR) && $(WX_ROOT)/configure $(WX_CONFIGURE_FLAGS) >/dev/null
	
	@echo Building wxWidgets library...
	cd $(WX_BUILD_DIR) && make
