#
# TrueCrypt Windows driver Makefile
#

# Windows Driver Development Kit base path
DDK = C:\WINDDK\3790.1830

!IFDEF WINDDK_3790_1830
DDK = $(WINDDK_3790_1830)
!ENDIF

BASENAME = truecrypt
OS = wxp
ARCH = i386
MACHINE = IX86
DEFS = -D_X86_ -Di386
CC = $(DDK)\bin\x86\cl.exe
LD = $(DDK)\bin\x86\link.exe

!IFDEF AMD64

BASENAME = truecrypt-x64
OS = wnet
ARCH = amd64
MACHINE = AMD64
DEFS = -DAMD64 -D_AMD64_
CC = $(DDK)\bin\win64\x86\amd64\cl.exe
LD = $(DDK)\bin\win64\x86\amd64\link.exe
 
!ENDIF


CFLAGS = -nologo $(CFLAGS) \
-EHs-c- -Zp8 -GS -Gy -cbstring -Gz -Gm- \
-GR- -GF -W3 -Wp64 -FI$(DDK)\inc\$(OS)\warning.h \
-I$(DDK)\inc\$(OS) -I$(DDK)\inc\ddk\$(OS) \
-I$(DDK)\inc\ddk\wdm\$(OS) -I$(DDK)\inc\crt \
-I..\..\Common -I..\..\Crypto -I..\..

DEFS = $(DEFS) -DNT4_DRIVER -DSTD_CALL -DCONDITION_HANDLING=1 \
-DNT_UP=1 -DNT_INST=0 -DWIN32=100 -D_NT1X_=100 \
-DWINNT=1 -D_WIN32_WINNT=0x0400 -DWIN32_LEAN_AND_MEAN=1 -DDEVL=1 \
-D_UNICODE -DLITTLE_ENDIAN -DFPO=0 -D_DLL=1 -D_IDWBUILD 

LINK_OPTS = -nologo -machine:$(MACHINE) \
-MERGE:_PAGE=PAGE -MERGE:_TEXT=.text -SECTION:INIT,d \
-INCREMENTAL:NO -FORCE:MULTIPLE -RELEASE -FULLBUILD \
-IGNORE:4001,4037,4039,4065,4070,4078,4087,4089,4096 -NODEFAULTLIB \
-MERGE:.rdata=.text -MAP:$(BASENAME).map -driver -align:0x20 \
-subsystem:native -base:0x10000 -entry:DriverEntry

OBJECTS = Aescrypt.obj Aeskey.obj Aestab.obj Bf_ecb.obj Bf_enc.obj Bf_skey.obj \
C_ecb.obj C_enc.obj C_skey.obj Des.obj Des_enc.obj Ecb3_enc.obj Rmd160.obj \
Serpent.obj Set_key.obj Sha1.obj Twofish.obj Whirlpool.obj \
Ntdriver.obj Ntvol.obj \
Cache.obj Crc.obj Crypto.obj Endian.obj GfMul.obj Pkcs5.obj Volumes.obj \
Tests.obj Driver.res

LIBS = $(DDK)\lib\$(OS)\$(ARCH)\ntoskrnl.lib \
$(DDK)\lib\$(OS)\$(ARCH)\hal.lib \
$(DDK)\lib\$(OS)\$(ARCH)\bufferoverflowK.lib


!IFDEF RELEASE

# Release
DEFS = $(DEFS) -DNO_DISK_ACCESS -DNDEBUG 
CFLAGS = $(CFLAGS) -Gs- -Oxs -Oy -w34244 -w34267 -w34189 -FAcs
COPYRELEASE = copy $(BASENAME).sys "..\..\Release\Setup files"

!ELSE

# Debug
CFLAGS = $(CFLAGS) -Gs -Z7 -Od -Oi -Oy- 
DEFS = $(DEFS) -DDBG=1 -D_DEBUG -DDEBUG -DRDRDBG -DSRVDBG -DDBG_MESSAGES=1
LINK_OPTS = -debug $(LINK_OPTS)
COPYRELEASE =

!ENDIF

CFLAGS = $(CFLAGS) $(DEFS)


all: $(BASENAME).sys
	
{..}.c{}.obj :
	@$(CC) -c $(CFLAGS) $<

{..\..\Common}.c{}.obj :
	@$(CC) -c $(CFLAGS) $<

{..\..\Crypto}.c{}.obj :
	@$(CC) -c $(CFLAGS) $<
		
{..}.rc{}.res :
	@echo Driver.rc
	@rc -r -fo Driver.res $< 

$(BASENAME).sys : $(OBJECTS) $(LIBS)
	@echo Linking...
	@echo $(BASENAME).sys
	@$(LD) $(LINK_OPTS) $(OBJECTS) $(LIBS) -out:$(BASENAME).sys
	@$(COPYRELEASE)
