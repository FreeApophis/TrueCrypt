/* The source code contained in this file has been derived from the source code
   of Encryption for the Masses 2.02a by Paul Le Roux. Modifications and
   additions to that source code contained in this file are Copyright (c) 2004
   TrueCrypt Foundation and Copyright (c) 2004 TrueCrypt Team. Unmodified
   parts are Copyright (c) 1998-99 Paul Le Roux. This is a TrueCrypt Foundation
   release. Please see the file license.txt for full license details. */

/* Everything below this line is automatically updated by the -mkproto-tool- */

int FormatVolume ( char *lpszFilename , BOOL bDevice , char *volumePath, unsigned __int64 size , unsigned __int64 hiddenVolHostSize , char *lpszPassword , int cipher , int pkcs5 , BOOL quickFormat, int fileSystem , int clusterSize, char * summaryMsg , HWND hwndDlg , BOOL hiddenVol , int *realClusterSize);
int FormatNoFs (unsigned __int64 startSector, __int64 num_sectors, HFILE dev, PCRYPTO_INFO cryptoInfo, int nFrequency, diskio_f write, BOOL quickFormat);
BOOL FormatNtfs (int driveNo, int clusterSize);
BOOL WriteSector ( HFILE dev , char *sector , char *write_buf , int *write_buf_cnt , __int64 *nSecNo , int *progress , PCRYPTO_INFO cryptoInfo , int nFrequency , diskio_f write );

#define WRITE_BUF_SIZE 65536

#define FILESYS_NONE	0
#define FILESYS_FAT		1
#define FILESYS_NTFS	2

// FMIFS

typedef BOOLEAN (__stdcall *PFMIFSCALLBACK)( int command, DWORD subCommand, PVOID parameter ); 
typedef VOID (__stdcall *PFORMATEX)( PWCHAR DriveRoot, DWORD MediaFlag, PWCHAR Format, PWCHAR Label, BOOL QuickFormat, DWORD ClusterSize, PFMIFSCALLBACK Callback );

#define FMIFS_DONE		0xB
#define FMIFS_HARDDISK	0xC
