/* Legal Notice: The source code contained in this file has been derived from
   the source code of Encryption for the Masses 2.02a, which is Copyright (c)
   1998-99 Paul Le Roux and which is covered by the 'License Agreement for
   Encryption for the Masses'. Modifications and additions to that source code
   contained in this file are Copyright (c) 2004-2005 TrueCrypt Foundation and
   Copyright (c) 2004 TrueCrypt Team, and are covered by TrueCrypt License 2.0
   the full text of which is contained in the file License.txt included in
   TrueCrypt binary and source code distribution archives.  */

#include "Common.h"

int FormatVolume ( char *lpszFilename , BOOL bDevice , char *volumePath, unsigned __int64 size , unsigned __int64 hiddenVolHostSize , Password *password , int cipher , int pkcs5 , BOOL quickFormat, int fileSystem , int clusterSize, wchar_t *summaryMsg , HWND hwndDlg , BOOL hiddenVol , int *realClusterSize);
int FormatNoFs (unsigned __int64 startSector, __int64 num_sectors, HFILE dev, PCRYPTO_INFO cryptoInfo, diskio_f write, BOOL quickFormat);
BOOL FormatNtfs (int driveNo, int clusterSize);
BOOL WriteSector ( HFILE dev , char *sector , char *write_buf , int *write_buf_cnt , __int64 *nSecNo , PCRYPTO_INFO cryptoInfo , diskio_f write );

#define WRITE_BUF_SIZE 65536

#define FILESYS_NONE	0
#define FILESYS_FAT		1
#define FILESYS_NTFS	2

// FMIFS

typedef BOOLEAN (__stdcall *PFMIFSCALLBACK)( int command, DWORD subCommand, PVOID parameter ); 
typedef VOID (__stdcall *PFORMATEX)( PWCHAR DriveRoot, DWORD MediaFlag, PWCHAR Format, PWCHAR Label, BOOL QuickFormat, DWORD ClusterSize, PFMIFSCALLBACK Callback );

#define FMIFS_DONE		0xB
#define FMIFS_HARDDISK	0xC
