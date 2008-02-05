/*
 Copyright (c) 2008 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.4 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include "Setup.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	// WARNING: file name is NOT null-terminated (use fileNameLength).
	unsigned char *fileName;
	int fileNameLength;
	__int32 crc;
	__int32 fileLength;
	unsigned char *fileContent;
} DECOMPRESSED_FILE;

extern DECOMPRESSED_FILE	Decompressed_Files [NBR_COMPRESSED_FILES];

void SelfExtractStartupInit (void);
BOOL SelfExtractInMemory (char *path);
void __cdecl ExtractAllFilesThread (void *hwndDlg);
BOOL MakeSelfExtractingPackage (HWND hwndDlg, char *szDestDir);
BOOL VerifyPackageIntegrity (void);
BOOL IsSelfExtractingPackage (void);
void DeobfuscateMagEndMarker (void);

extern char DestExtractPath [TC_MAX_PATH];

#ifdef __cplusplus
}
#endif
