#
# Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.
#
# Governed by the TrueCrypt License 2.4 the full text of which is contained
# in the file License.txt included in TrueCrypt binary and source code
# distribution packages.
#

PROJ = BootLoader
.SILENT:

!ifndef MSVC16_ROOT
!error Environment variable MSVC16_ROOT must point to the installation directory of MS Visual C++ 1.5
!endif

ENVPATH = $(PATH)

CPP = $(MSVC16_ROOT)\bin\cl.exe
LD = $(MSVC16_ROOT)\bin\link.exe

AFLAGS = /nologo /AT /omf

CPPFLAGS = /nologo /W2 /Fc /I "$(MSVC16_ROOT)\Include" /I"..\..\.." /I"..\..\..\Common" /I"..\..\..\Crypto"
CPPFLAGS = $(CPPFLAGS) /D __int8=char /D __int16=int /D __int32=long /D BOOL=__int32 /D FALSE=0 /D TRUE=1
CPPFLAGS = $(CPPFLAGS) /D LITTLE_ENDIAN=1234 /D BYTE_ORDER=1234 /D TC_WINDOWS_BOOT /D TC_MINIMIZE_CODE_SIZE /D TC_NO_COMPILER_INT64
CPPFLAGS = $(CPPFLAGS) /D malloc=malloc_NA

LFLAGS = /NOLOGO /ONERROR:NOEXE /NOI /BATCH


!ifdef DEBUG

OBJDIR = Debug
OUTDIR = $(OBJDIR)
TARGETEXT = exe
CPPFLAGS = $(CPPFLAGS) /AM /Zl /G2 /D _DEBUG /D DEBUG /Od /Z7 /D_DOS
LFLAGS = $(LFLAGS) /CO /STACK:32768
OBJS =
LIBS = mlibce
PROJDIR = ..

!else

OBJDIR = Release
OUTDIR = $(OBJDIR)
TARGETEXT = com
TARGETS = $(OUTDIR)\BootDefs.i $(OUTDIR)\BootSector.bin
CPPFLAGS = $(CPPFLAGS) /AT /Zl /f- /G3 /Oe /Os /Ob1 /OV0 /Gs /Gf /Gy /D NDEBUG
LFLAGS = $(LFLAGS) /NOD /NOE /TINY
OBJS = $(OUTDIR)\BootCrt.obj
LIBS = slibce

!endif


TARGETS = $(TARGETS) $(OUTDIR)\$(PROJ).$(TARGETEXT)

OBJS = $(OBJS) $(OUTDIR)\BootConfig.obj
OBJS = $(OBJS) $(OUTDIR)\BootConsoleIo.obj
OBJS = $(OBJS) $(OUTDIR)\BootDebug.obj
OBJS = $(OBJS) $(OUTDIR)\BootDiskIo.obj
OBJS = $(OBJS) $(OUTDIR)\BootEncryptedIo.obj
OBJS = $(OBJS) $(OUTDIR)\BootMain.obj
OBJS = $(OBJS) $(OUTDIR)\IntFilter.obj
OBJS = $(OBJS) $(OUTDIR)\Platform.obj

OBJS = $(OBJS) $(OUTDIR)\Crc.obj
OBJS = $(OBJS) $(OUTDIR)\Crypto.obj
OBJS = $(OBJS) $(OUTDIR)\Endian.obj
OBJS = $(OBJS) $(OUTDIR)\Pkcs5.obj
OBJS = $(OBJS) $(OUTDIR)\Volumes.obj
OBJS = $(OBJS) $(OUTDIR)\Xts.obj

OBJS = $(OBJS) $(OUTDIR)\AesSmall.obj
OBJS = $(OBJS) $(OUTDIR)\Serpent.obj
OBJS = $(OBJS) $(OUTDIR)\Twofish.obj
OBJS = $(OBJS) $(OUTDIR)\Rmd160.obj


all: env $(TARGETS)

env:
	set INCLUDE=.
	set LIB=.
	set LIBPATH=.
	
clean:
	-del /q /s $(OBJDIR) >NUL:


.asm{$(OUTDIR)}.obj:
	cd $(OBJDIR)
	$(AS) $(AFLAGS) /c ..\$<
	cd ..

{..\..\Crypto}.c{$(OUTDIR)}.obj:
	cd $(OBJDIR)
	set PATH=.
	$(CPP) $(CPPFLAGS) /c ..\$<
	set PATH=$(ENVPATH)
	cd ..
	
{..\..\Common}.c{$(OUTDIR)}.obj:
	cd $(OBJDIR)
	set PATH=.
	$(CPP) $(CPPFLAGS) /c ..\$<
	set PATH=$(ENVPATH)
	cd ..
		
.cpp{$(OUTDIR)}.obj:
	cd $(OBJDIR)
	set PATH=.
	$(CPP) $(CPPFLAGS) /c ..\$<
	set PATH=$(ENVPATH)
	cd ..

$(OUTDIR)\BootDefs.i: BootDefs.h
	cd $(OBJDIR)
	set PATH=.
	$(CPP) /nologo /D TC_ASM_PREPROCESS /P /EP ..\BootDefs.h
	set PATH=$(ENVPATH)
	cd ..
	
$(OUTDIR)\BootSector.bin: $(OUTDIR)\BootSector.obj
	cd $(OBJDIR)
	$(LD) $(LFLAGS) BootSector.obj,BootSector.bin,,,, >NUL:
	-dd.exe conv=notrunc bs=512 conv=notrunc if=BootSector.bin of=$(PROJ).flp 2>NUL:
	cd ..


$(OUTDIR)\$(PROJ).$(TARGETEXT): $(OBJS)
	@echo Linking...
	cd $(OBJDIR)
	
	echo >NUL: @<<$(PROJ).crf2
		
$(PROJ).$(TARGETEXT)
$(PROJ).map
$(MSVC16_ROOT)\lib\+
$(LIBS)
;
<<
	del $(PROJ).crf >NUL: 2>NUL:
	for %F in ($(**F)) do @echo %F + >>$(PROJ).crf
	type $(PROJ).crf2 >>$(PROJ).crf
	
	$(LD) $(LFLAGS) @$(PROJ).crf
	del $(PROJ).crf $(PROJ).crf2

!ifndef DEBUG
	-dd.exe conv=notrunc,sync bs=512 seek=1 if=$(PROJ).$(TARGETEXT) of=$(PROJ).flp 2>NUL:
!endif
	cd ..
