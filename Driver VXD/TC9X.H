/* Copyright (C) 2004 TrueCrypt Team, truecrypt.org
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

typedef struct cryptvol
{
	PDCB ldcb;
	PDCB filehostdcb;       /* File host device, or main dcb if partition */
	int booted;             /* 0,1,2,256 depending on boot and error
				   state of volume */
	int drive;              /* Dos drive number */
	ULONG cryptsectorfirst; /* 0x00000000 or starting sector (partitions) */
	ULONG cryptsectorlast;  /* 0x7ffffff0 or last sector (partitions) */
	PDCB physdevDCB;
	int mountfilehandle;    /* 0x00000000 for partitions */

	DDB addb;               /* Calldown ddb ptr, used only by
				   IspInsertCalldown */
	DCB logicaldcb;

	PCRYPTO_INFO cryptoInfo;/* Encryption specific data */

	int notifytime;		/* Supports the PNP msg needed for Windows to 'see' a new drive */

	char mounted_file_name[512];    /* The mounted volume name, or
					   \Device\... for partitions */

} cryptvol;

typedef struct partitionrec
{
	unsigned char boot;
	unsigned char sh;
	unsigned char ss;
	unsigned char sc;
	unsigned char system;
	unsigned char eh;
	unsigned char es;
	unsigned char ec;
	unsigned int StartSector;
	unsigned int NumSectors;
} partitionrec;

#define ior iop->IOP_ior

#ifndef arraysize
#define arraysize(p) (sizeof(p)/sizeof((p)[0]))
#endif

/* Everything below this line is automatically updated by the -mkproto-tool- */

VOID OnAsyncRequest ( PAEP aep );
USHORT OnInitialize ( PAEP_bi_init aep );
USHORT OnUninitialize ( PAEP_bi_uninit aep );
USHORT OnBootComplete ( PAEP_boot_done aep );
USHORT OnConfigDcb ( PAEP_dcb_config aep );
USHORT OnUnconfigDcb ( PAEP_dcb_unconfig aep );
VOID OnRequest ( PIOP iop );
int cmpvend ( char *a , char *b , int len );
int CheckDcbAlready ( PDCB dcb );
void DoCallDown ( PIOP iop );
BOOL OnSysDynamicDeviceInit ( void );
BOOL OnSysDynamicDeviceExit ( void );
DWORD OnDeviceIoControl ( PDIOCPARAMETERS p );
BOOL Kill_Drive ( cryptvol *cv );
int closeCrDevice ( cryptvol *cv , int mode );
int installthread ( void *t );
void sectorcopy ( char *dest , char *source , int num );
void cryptproc ( PIOP iop , cryptvol *cv );
void DoCallBack ( PIOP iop );
VOID partfilerequest ( PIOP iop );
int Add_Drive ( PDCB dcb , cryptvol *cv , int prefdrive );
int trymountfile ( PDCB dcb , cryptvol *cv , MOUNT_STRUCT *mf );
void readnullfilesize ( int hand );
void mountdiskfileR0 ( MOUNT_STRUCT *mf );
void outblock ( PIOP iop , char *outbuffer , int sectorstart , int sectorcount , cryptvol *cv , char *workbuff );
void inblock ( PIOP iop , char *outbuffer , int sectorstart , int sectorcount , cryptvol *cv );
int doR0fileio ( int sector , int numsectors , char *buffer , cryptvol *cv , int iorop );
int MapDosError ( int error );
int dophysblock2 ( PIOP iop , int sector , int numsectors , char *buffr , cryptvol *cv , USHORT iorop );
int dophysblock ( PIOP iop , int sector , int numsectors , char *buffr , cryptvol *cv , USHORT iorop );
void readlogical ( PIOP iop , int temp_block , int num_sectors , char *buffer , cryptvol *cv );
void writelogical ( PIOP iop , int temp_block , int num_sectors , char *buffer , cryptvol *cv );
BOOL OnSystemExit ( void );
void Post_message ( char *msg , char *header );
void ProcessWinMessagesBlueScreen ( void );
USHORT OnHalfSec ( PAEP_boot_done aep );
void readallpartitions ( MOUNT_STRUCT *mf , BOOL bVerifyOnly );
int DiskRead ( PDCB mydcb , PIOP myiop , unsigned int sector , unsigned int numsectors , char *buffr , USHORT iorop );
void UsePartitionInfo ( PDCB dcb , PIOP myiop , char *diskbuffer , unsigned int relative , int recursed , int *partnum , MOUNT_STRUCT *mf , BOOL bVerifyOnly );
int tryvol ( PDCB dcb , PIOP myiop , partitionrec *pr , MOUNT_STRUCT *mf , cryptvol **pcv );
struct cryptvol *checkpartition ( PIOP iop , partitionrec *pr );
int cmppart ( PDCB dcb , unsigned int secstart , cryptvol *cv );
struct cryptvol *addcryptedpartition ( PIOP iop , char *peek );
int tryaddpart ( cryptvol *cv , unsigned int secstart , unsigned int seclast , PDCB device );
int unlockdrive ( cryptvol *cv );
int lockdrive ( PDCB mydcb , PIOP myiop , int lockmode );
int AppAccessBlockDevice ( unsigned int devicenum , unsigned int sectorstart , unsigned int sectorlen , char *buffer , int mode );
void drivearrived ( void );
