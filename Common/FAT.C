/* Copyright (C) 2004 TrueCrypt Foundation
   This product uses components written by Paul Le Roux <pleroux@swprofessionals.com> */

#include "TCdefs.h"

#include "crypto.h"
#include "random.h"
#include "fat.h"
#include "progress.h"


#include <time.h>

#define WRITE_BUF_SIZE 65536

void
GetFatParams (fatparams * ft)
{
	int fatsecs;

	if(ft->cluster_size == 0)
	{
		if (ft->num_sectors >= 1024I64 *1024*1024*2)
			ft->cluster_size = 128;
		else if (ft->num_sectors >= 256*1024*1024*2)
			ft->cluster_size = 64;
		else if (ft->num_sectors >= 32*1024*1024*2)
			ft->cluster_size = 32;
		else if (ft->num_sectors >= 8*1024*1024*2)
			ft->cluster_size = 16;
		else if (ft->num_sectors >= 512*1024*2)
			ft->cluster_size = 8;
		else if (ft->num_sectors >= 64*1024*2)
			ft->cluster_size = 4;
		else if (ft->num_sectors >= 66600)
			ft->cluster_size = 2;
		else
			ft->cluster_size = 1;
	}

/*	for (j = 2;; j = j << 1)
	{
		if ((ft->num_sectors * SECTOR_SIZE) / SECTOR_SIZE / j < 65536)
			break;
	}

	ft->secs_track = (ft->num_sectors * SECTOR_SIZE) / SECTOR_SIZE / j;
	ft->heads = j;
*/

	// Geometry always set to SECTORS/1/1
	ft->secs_track = 1; 
	ft->heads = 1; 

	ft->dir_entries = 512;
	ft->fats = 2;
	ft->create_time = (long) time (NULL);
	ft->media = 0xf8;
	ft->sector_size = SECTOR_SIZE;
	ft->hidden = 0;

	ft->size_root_dir = ft->dir_entries * 32;
	fatsecs = ft->num_sectors - (ft->size_root_dir + SECTOR_SIZE + 1) / SECTOR_SIZE - 1;

	ft->size_fat = 12;
	ft->cluster_count = (int) (((__int64) fatsecs * SECTOR_SIZE) /
	    (ft->cluster_size * SECTOR_SIZE + 3));
	ft->fat_length = (((ft->cluster_count * 3 + 1) >> 1) + SECTOR_SIZE + 1) /
	    SECTOR_SIZE;

	if (ft->cluster_count >= 4085) //FAT16
	{
		ft->size_fat = 16;
		ft->cluster_count = (int) (((__int64) fatsecs * SECTOR_SIZE) /
		    (ft->cluster_size * SECTOR_SIZE + 4));
		ft->fat_length = (ft->cluster_count * 2 + SECTOR_SIZE + 1) /
		    SECTOR_SIZE;
	}
	if(ft->cluster_count >= 65525) //FAT32
	{
		ft->size_fat = 32;
		fatsecs = ft->num_sectors - 32 - ft->cluster_size * SECTOR_SIZE;
		ft->size_root_dir = ft->cluster_size * SECTOR_SIZE;
		ft->cluster_count = (int) (((__int64) fatsecs * SECTOR_SIZE) /
		    (ft->cluster_size * SECTOR_SIZE + 4));
		ft->fat_length = (ft->cluster_count * 4 + SECTOR_SIZE + 1) /
		    SECTOR_SIZE;
	}

	/* MS recommended cut-over safety net for buggy code out there */
	#define UNSAFE_AREA 32
	if(ft->cluster_count > 4085-UNSAFE_AREA  &&  ft->cluster_count < 4085)
		ft->cluster_count = 4085-UNSAFE_AREA;

	if(ft->cluster_count > 65525-UNSAFE_AREA  &&  ft->cluster_count < 65525)
		ft->cluster_count = 65525-UNSAFE_AREA;


	if (ft->num_sectors >= 65536 || ft->size_fat == 32)
	{
		ft->sectors = 0;
		ft->total_sect = ft->num_sectors;
	}
	else
	{
		ft->sectors = ft->num_sectors;
		ft->total_sect = 0;
	}


}

void
PutBoot (fatparams * ft, unsigned char *boot)
{
	int cnt = 0;

	boot[cnt++] = 0xeb;	/* boot jump */
	boot[cnt++] = 0x3c;
	boot[cnt++] = 0x90;
	memcpy (boot + cnt, "MSWIN4.1", 8); /* system id */
	cnt += 8;
	memcpy (boot + cnt, (short *) &ft->sector_size, 2);	/* bytes per sector */
	cnt += 2;
	memcpy (boot + cnt, (char *) &ft->cluster_size, 1);	/* sectors per cluster */
	cnt++;
	boot[cnt++] = ft->size_fat == 32 ? 32 : 1;	/* reserved sectors */
	boot[cnt++] = 0x00;
	memcpy (boot + cnt, (char *) &ft->fats, 1);	/* 2 fats */
	cnt++;

	if(ft->size_fat == 32)
	{
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x00;
	}
	else
	{
		memcpy (boot + cnt, (short *) &ft->dir_entries, 2);	/* 512 root entries */
		cnt += 2;
	}

	memcpy (boot + cnt, (short *) &ft->sectors, 2);	/* # sectors */
	cnt += 2;
	memcpy (boot + cnt, (char *) &ft->media, 1);	/* media byte */
	cnt++;

	if(ft->size_fat == 32)	
	{
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x00;
	}
	else 
	{ 
		memcpy (boot + cnt, (short *) &ft->fat_length, 2);	/* fat size */
		cnt += 2;
	}

	memcpy (boot + cnt, (short *) &ft->secs_track, 2);	/* # sectors per track */
	cnt += 2;
	memcpy (boot + cnt, (short *) &ft->heads, 2);	/* # heads */
	cnt += 2;
	boot[cnt++] = 0x00;	/* 0 hidden sectors */
	boot[cnt++] = 0x00;
	boot[cnt++] = 0x00;
	boot[cnt++] = 0x00;
	memcpy (boot + cnt, (long *) &ft->total_sect, 4);	/* # huge sectors */

	cnt += 4;

	if(ft->size_fat == 32)
	{
		memcpy (boot + cnt, &ft->fat_length, 4); cnt += 4;	/* fat size 32 */
		boot[cnt++] = 0x01;	/* ExtFlags */
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x00;	/* FSVer */
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x02;	/* RootClus */
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x01;	/* FSInfo */
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x06;	/* BkBootSec */
		boot[cnt++] = 0x00;
		memset(boot+cnt, 0, 12); cnt+=12;	/* Reserved */
		
	}

	boot[cnt++] = 0x80;	/* drive number */   // FIXED 80 > 00
	boot[cnt++] = 0x00;	/* reserved */
	boot[cnt++] = 0x29;	/* boot sig */
	memcpy (boot + cnt, (long *) &ft->create_time, 4);	/* vol id */
	cnt += 4;
	memcpy (boot + cnt, (char *) ft->volume_name, 11);	/* vol title */
	cnt += 11;

	switch(ft->size_fat) /* filesystem type */
	{
		case 12: memcpy (boot + cnt, "FAT12   ", 8); break;
		case 16: memcpy (boot + cnt, "FAT16   ", 8); break;
		case 32: memcpy (boot + cnt, "FAT32   ", 8); break;
	}
	cnt += 8;

	memset (boot + cnt, 0, ft->size_fat==32 ? 420:448);	/* boot code */
	cnt += ft->size_fat==32 ? 420:448;
	boot[cnt++] = 0x55;
	boot[cnt++] = 0xaa;	/* boot sig */
}

/* FAT32 FSInfo */
PutFSInfo (unsigned char *sector)
{

		memset (sector, 0, 512);
		sector[3]=0x41; /* LeadSig */
		sector[2]=0x61; 
		sector[1]=0x52; 
		sector[0]=0x52; 
		sector[484+3]=0x61; /* StrucSig */
		sector[484+2]=0x41; 
		sector[484+1]=0x72; 
		sector[484+0]=0x72; 
		sector[488+3]=0xff; /* Free_Count */
		sector[488+2]=0xff;
		sector[488+1]=0xff;
		sector[488+0]=0xff;
		sector[492+3]=0xff; /* Nxt_Free */
		sector[492+2]=0xff;
		sector[492+1]=0xff;
		sector[492+0]=0xff;
		sector[508+3]=0xaa; /* TrailSig */
		sector[508+2]=0x55;
		sector[508+1]=0x00;
		sector[508+0]=0x00;
}

BOOL
WriteSector (HFILE dev, char *sector,
	     char *write_buf, int *write_buf_cnt,
	     __int64 *nSecNo, int *progress, PCRYPTO_INFO cryptoInfo,
	     int nFrequency, diskio_f write)
{
	(*cryptoInfo->encrypt_sector) ((unsigned long *) sector,
	(*nSecNo)++, 1, cryptoInfo->ks, cryptoInfo->iv, cryptoInfo->cipher);
	memcpy (write_buf + *write_buf_cnt, sector, SECTOR_SIZE);
	(*write_buf_cnt) += SECTOR_SIZE;


	if (*write_buf_cnt == WRITE_BUF_SIZE)
	{
		if ((*write) (dev, write_buf, WRITE_BUF_SIZE) == HFILE_ERROR)
			return FALSE;
		else
			*write_buf_cnt = 0;
	}

	if (++(*progress) == nFrequency)
	{
		if (UpdateProgressBar (*nSecNo) == TRUE)
			return FALSE;
		*progress = 0;
	}

	return TRUE;

}

int
Format (fatparams * ft, HFILE dev, PCRYPTO_INFO cryptoInfo, int nFrequency, diskio_f write, BOOL quickFormat)
{
	int write_buf_cnt = 0;
	char sector[SECTOR_SIZE], *write_buf;
	int progress = 0;
	unsigned __int64 nSecNo = 1;
	int x, n;

	if ((*write) (dev, (char *) &ft->header, SECTOR_SIZE) == HFILE_ERROR)
		return ERR_OS_ERROR;

	write_buf = TCalloc (WRITE_BUF_SIZE);

	memset (sector, 0, sizeof (sector));

	PutBoot (ft, (unsigned char *) sector);
	if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
		cryptoInfo, nFrequency, write) == FALSE)
		goto fail;

	/* fat32 boot area */
	if (ft->size_fat == 32)				
	{
		/* fsinfo */
		PutFSInfo((unsigned char *) sector);
		if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
			cryptoInfo, nFrequency, write) == FALSE)
			goto fail;

		/* reserved */
		while (nSecNo<=6)
		{
			memset (sector, 0, sizeof (sector));
			sector[508+3]=0xaa; /* TrailSig */
			sector[508+2]=0x55;
			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
				cryptoInfo, nFrequency, write) == FALSE)
				goto fail;
		}
		
		/* bootsector backup */
		memset (sector, 0, sizeof (sector));
		PutBoot (ft, (unsigned char *) sector);
		if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
				 cryptoInfo, nFrequency, write) == FALSE)
			goto fail;

		PutFSInfo((unsigned char *) sector);
		if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
			cryptoInfo, nFrequency, write) == FALSE)
			goto fail;

		/* reserved */
		while (nSecNo<=32)
		{
			memset (sector, 0, sizeof (sector));
			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
				cryptoInfo, nFrequency, write) == FALSE)
				goto fail;
		}
	}


	/* write fat */
	for (x = 1; x <= ft->fats; x++)
	{
		for (n = 0; n < ft->fat_length; n++)
		{
			memset (sector, 0, SECTOR_SIZE);

			if (n == 0)
			{
				unsigned char fat_sig[12];
				if (ft->size_fat == 32)
				{
					fat_sig[0] = (unsigned char) ft->media;
					fat_sig[1] = fat_sig[2] = 0xff;
					fat_sig[3] = 0x0f;
					fat_sig[4] = fat_sig[5] = fat_sig[6] = 0xff;
					fat_sig[7] = 0x0f;
					fat_sig[8] = fat_sig[9] = fat_sig[10] = 0xff;
					fat_sig[11] = 0x0f;
					memcpy (sector, fat_sig, 12);
				}				
				else if (ft->size_fat == 16)
				{
					fat_sig[0] = (unsigned char) ft->media;
					fat_sig[1] = 0xff;
					fat_sig[2] = 0xff;
					fat_sig[3] = 0xff;
					memcpy (sector, fat_sig, 4);
				}
				else if (ft->size_fat == 12)
				{
					fat_sig[0] = (unsigned char) ft->media;
					fat_sig[1] = 0xff;
					fat_sig[2] = 0xff;
					fat_sig[3] = 0x00;
					memcpy (sector, fat_sig, 4);
				}
			}

			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
				    cryptoInfo, nFrequency, write) == FALSE)
				goto fail;
		}
	}


	/* write rootdir */
	for (x = 0; x < ft->size_root_dir / SECTOR_SIZE; x++)
	{
		memset (sector, 0, SECTOR_SIZE);
		if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
				 cryptoInfo, nFrequency, write) == FALSE)
			goto fail;

	}

	/* write data area */
	if(!quickFormat)
	{
		char key[MAX_CIPHER_KEY];

		// Generate a random key and IV to randomize data area
		// and support a possible hidden volume
		RandgetBytes (key, MAX_CIPHER_KEY, FALSE); 
		RandgetBytes (cryptoInfo->iv, sizeof cryptoInfo->iv, FALSE); 
		init_cipher (cryptoInfo->cipher, key, cryptoInfo->ks);
		ZeroMemory (sector, 512); 

		x = ft->num_sectors - (ft->size_fat==32 ? 32 : 1) - ft->size_root_dir / SECTOR_SIZE - ft->fat_length * 2;
		while (x--)
		{
			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, &progress,
				cryptoInfo, nFrequency, write) == FALSE)
				goto fail;
		}
	}

	if (write_buf_cnt != 0 && (*write) (dev, write_buf, write_buf_cnt) == HFILE_ERROR)
		goto fail;

	UpdateProgressBar (nSecNo);

	TCfree (write_buf);
	return 0;

      fail:

	TCfree (write_buf);
	return ERR_OS_ERROR;
}
