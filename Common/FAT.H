/* Copyright (C) 2004 TrueCrypt Team, truecrypt.org
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

typedef struct fatparams_t
{
	char volume_name[11];
	int num_sectors;	/* total number of sectors */
	int cluster_count;	/* number of clusters */
	int size_root_dir;	/* size of the root directory in bytes */
	int size_fat;		/* size of FAT */
	int fats;
	long create_time;
	int media;
	int cluster_size;
	int fat_length;
	int dir_entries;
	int sector_size;
	int hidden;
	int sectors;
	long total_sect;

	int heads;
	int secs_track;

	char header[SECTOR_SIZE];
} fatparams;


struct msdos_boot_sector
{
	unsigned char boot_jump[3];	/* Boot strap short or near jump */
	char system_id[8];	/* Name - can be used to special case
				   partition manager volumes */
	unsigned char sector_size[2];	/* bytes per logical sector */
	unsigned char cluster_size;	/* sectors/cluster */
	unsigned short reserved;/* reserved sectors */
	unsigned char fats;	/* number of FATs */
	unsigned char dir_entries[2];	/* root directory entries */
	unsigned char sectors[2];	/* number of sectors */
	unsigned char media;	/* media code  */
	unsigned short fat_length;	/* sectors/FAT */
	unsigned short secs_track;	/* sectors per track */
	unsigned short heads;	/* number of heads */
	unsigned long hidden;	/* hidden sectors */
	unsigned long total_sect;	/* number of sectors (if sectors ==
					   0) */
	unsigned char drive_number;	/* BIOS drive number */
	unsigned char RESERVED;	/* Unused */
	unsigned char ext_boot_sign;	/* 0x29 if fields below exist (DOS
					   3.3+) */
	unsigned char volume_id[4];	/* Volume ID number */
	char volume_label[11];	/* Volume label */
	char fs_type[8];	/* Typically FAT12 or FAT16 */
	unsigned char boot_code[448];	/* Boot code (or message) */
	unsigned short boot_sign;	/* 0xAA55 */
};


/* Everything below this line is automatically updated by the -mkproto-tool- */

void GetFatParams ( fatparams *ft );
void PutBoot ( fatparams *ft , unsigned char *boot );
BOOL WriteSector ( HFILE dev , char *sector , char *write_buf , int *write_buf_cnt , __int64 *nSecNo , int *progress , PCRYPTO_INFO cryptoInfo , int nFrequency , diskio_f write );
int Format (fatparams * ft, HFILE dev, PCRYPTO_INFO cryptoInfo, int nFrequency, diskio_f write, BOOL quickFormat);
