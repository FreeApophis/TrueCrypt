/*
 Copyright (c) TrueCrypt Foundation. All rights reserved.

 Covered by the TrueCrypt License 2.2 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/ctype.h>
#include <linux/device-mapper.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <dm.h>

#include "Tcdefs.h"
#include "Crypto.h"
#include "Tests.h"
#include "Dm-target.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,5)
#error Linux kernel 2.6.5 or later required
#endif

int trace_level = 0;

#define MSG_PREFIX "truecrypt: "
#define error(fmt, args...) printk(KERN_ERR MSG_PREFIX fmt, ## args)
#define trace(level, fmt, args...) level <= trace_level && printk(KERN_DEBUG MSG_PREFIX fmt, ## args)
#define dbg(fmt, args...) printk(KERN_DEBUG MSG_PREFIX fmt, ## args)

#define MIN_POOL_SIZE 16

#ifndef __GFP_NOMEMALLOC
#define __GFP_NOMEMALLOC 0
#endif

struct target_ctx
{
	struct dm_dev *dev;
	sector_t start;
	char *volume_path;
	mempool_t *bio_ctx_pool;
	mempool_t *pg_pool;
	unsigned long long read_only_start;
	unsigned long long read_only_end;
	unsigned long long uid;
	unsigned long long mtime;
	unsigned long long atime;
	int flags;
	PCRYPTO_INFO ci;
};

struct bio_ctx
{
	struct dm_target *target;
	struct bio *orig_bio;
	atomic_t ref_count;
	u64 crypto_sector;
	int error;
	struct work_struct work;
};

static struct workqueue_struct *work_queue = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
static struct kmem_cache *bio_ctx_cache = NULL;
#else
static kmem_cache_t *bio_ctx_cache = NULL;
#endif

#define READ_ONLY(tc) (tc->flags & TC_READ_ONLY)
#define HID_VOL_PROT(tc) (tc->flags & TC_HIDDEN_VOLUME_PROTECTION)


static int hex2bin (char *hex_string, u8 *byte_buf, int max_length)
{
	int i = 0, n;
	char s[3];
	s[2] = 0;

	while (i < max_length
		&& (s[0] = *hex_string++) 
		&& (s[1] = *hex_string++))
	{
		if (sscanf (s, "%x", &n) != 1)
			return 0;
		byte_buf[i++] = (u8) n;
	}

	return i;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define congestion_wait blk_congestion_wait
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
static void *mempool_alloc_pg (gfp_t gfp_mask, void *pool_data)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
static void *mempool_alloc_pg (unsigned int gfp_mask, void *pool_data)
#else
static void *mempool_alloc_pg (int gfp_mask, void *pool_data)
#endif
{
	return alloc_page (gfp_mask);
}

static void mempool_free_pg (void *element, void *pool_data)
{
	__free_page (element);
}

#endif // LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)


static void *malloc_wait (mempool_t *pool, int direction)
{
	void *p;
	while (1)
	{
		p = mempool_alloc (pool, GFP_NOIO | __GFP_NOMEMALLOC);

		if (p)
			return p;

		congestion_wait (direction, HZ / 50);
	}
}


static void wipe_args (unsigned int argc, char **argv)
{
	int i;
	for (i = 0; i < argc; i++)
	{
		if (argv[i] != NULL)
			burn (argv[i], strlen (argv[i]));
	}
}


static int truecrypt_ctr (struct dm_target *ti, unsigned int argc, char **argv)
{
	struct target_ctx *tc;
	int key_size;
	int error = -EINVAL;
	unsigned long long sector;

	if (argc != TC_LAST_ARG + 1)
	{
		ti->error = "truecrypt: Usage: <start_sector> <sector_count> truecrypt <EA> <mode> <key> <key2/IV> <host_device> <sector_offset> <read_only_start> <read_only_end> <mtime> <atime> <flags> <volume_path>";
		return -EINVAL;
	}

	tc = kmalloc (sizeof (*tc), GFP_KERNEL);
	if (tc == NULL)
	{
		ti->error = "truecrypt: Cannot allocate target context";
		error = -ENOMEM;
		goto err;
	}
	memset (tc, 0, sizeof (*tc));

	tc->ci = crypto_open ();
	if (tc == NULL)
	{
		ti->error = "truecrypt: Cannot allocate crypto_info";
		error = -ENOMEM;
		goto err;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17)
	tc->bio_ctx_pool = mempool_create_slab_pool (MIN_POOL_SIZE, bio_ctx_cache);
#else
	tc->bio_ctx_pool = mempool_create (MIN_POOL_SIZE, mempool_alloc_slab, mempool_free_slab, bio_ctx_cache);
#endif

	if (!tc->bio_ctx_pool)
	{
		ti->error = "truecrypt: Cannot create bio context memory pool";
		error = -ENOMEM;
		goto err;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17)
	tc->pg_pool = mempool_create_page_pool (MIN_POOL_SIZE, 0);
#else
	tc->pg_pool = mempool_create (MIN_POOL_SIZE, mempool_alloc_pg, mempool_free_pg, NULL);
#endif
	if (!tc->pg_pool)
	{
		ti->error = "truecrypt: Cannot create page memory pool";
		error = -ENOMEM;
		goto err;
	}

	if (sscanf (argv[TC_ARG_SEC], "%llu", &sector) != 1)
	{
		ti->error = "truecrypt: Invalid device sector";
		goto err;
	}
	tc->start = sector;

	if (dm_get_device (ti, argv[TC_ARG_DEV], tc->start, ti->len, dm_table_get_mode (ti->table), &tc->dev))
	{
		ti->error = "truecrypt: Device lookup failed";
		goto err;
	}

	// Encryption algorithm
	tc->ci->ea = 0;
	if (sscanf (argv[TC_ARG_EA], "%d", &tc->ci->ea) != 1
		|| tc->ci->ea < EAGetFirst ()
		|| tc->ci->ea > EAGetCount ())
	{
		ti->error = "truecrypt: Invalid encryption algorithm";
		goto err;
	}

	// Mode of operation
	tc->ci->mode = 0;
	if (sscanf (argv[TC_ARG_MODE], "%d", &tc->ci->mode) != 1
		|| tc->ci->mode < 1
		|| tc->ci->mode >= INVALID_MODE)
	{
		ti->error = "truecrypt: Invalid mode of operation";
		goto err;
	}

	// Key
	key_size = EAGetKeySize (tc->ci->ea);
	if (hex2bin (argv[TC_ARG_KEY], tc->ci->master_key, key_size) != key_size)
	{
		ti->error = "truecrypt: Invalid key";
		goto err;
	}
	
	// EA init
	if (EAInit (tc->ci->ea, tc->ci->master_key, tc->ci->ks) == ERR_CIPHER_INIT_FAILURE)
	{
		ti->error = "truecrypt: Encryption algorithm initialization failed";
		goto err;
	}

	// Key2 / IV
	if (hex2bin (argv[TC_ARG_IV], tc->ci->iv, sizeof (tc->ci->iv)) != sizeof (tc->ci->iv))
	{
		ti->error = "truecrypt: Invalid IV";
		goto err;
	}

	// Mode init	
	if (!EAInitMode (tc->ci))
	{
		ti->error = "truecrypt: Mode of operation initialization failed";
		goto err;
	}

	// Read-only start sector
	if (sscanf (argv[TC_ARG_RO_START], "%llu", &tc->read_only_start) != 1)
	{
		ti->error = "truecrypt: Invalid read-only start sector";
		goto err;
	}

	// Read-only end sector
	if (sscanf (argv[TC_ARG_RO_END], "%llu", &tc->read_only_end) != 1)
	{
		ti->error = "truecrypt: Invalid read-only end sector";
		goto err;
	}

	// User ID
	if (sscanf (argv[TC_ARG_UID], "%llu", &tc->uid) != 1)
	{
		ti->error = "truecrypt: Invalid user ID";
		goto err;
	}

	// Modification time
	if (sscanf (argv[TC_ARG_MTIME], "%llu", &tc->mtime) != 1)
	{
		ti->error = "truecrypt: Invalid modification time";
		goto err;
	}

	// Access time
	if (sscanf (argv[TC_ARG_ATIME], "%llu", &tc->atime) != 1)
	{
		ti->error = "truecrypt: Invalid access time";
		goto err;
	}

	// Flags
	if (sscanf (argv[TC_ARG_FLAGS], "%d", &tc->flags) != 1)
	{
		ti->error = "truecrypt: Invalid flags";
		goto err;
	}

	// Volume path
	tc->volume_path = kmalloc (strlen (argv[TC_ARG_VOL]) + 1, GFP_KERNEL);
	if (tc->volume_path == NULL)
	{
		ti->error = "truecrypt: Cannot allocate volume path buffer";
		error = -ENOMEM;
		goto err;
	}
	strcpy (tc->volume_path, argv[TC_ARG_VOL]);

	// Hidden volume
	if (tc->start > 1)
	{
		tc->ci->hiddenVolume = TRUE;
		tc->ci->hiddenVolumeOffset = tc->start * SECTOR_SIZE;
	}

	ti->private = tc;

	wipe_args (argc, argv);
	return 0;

err:
	if (tc)
	{
		if (tc->ci)
			crypto_close (tc->ci);
		if (tc->volume_path)
			kfree (tc->volume_path);
		if (tc->bio_ctx_pool)
			mempool_destroy (tc->bio_ctx_pool);
		if (tc->pg_pool)
			mempool_destroy (tc->pg_pool);
		kfree (tc);
	}

	wipe_args (argc, argv);
	return error;
}


static void truecrypt_dtr (struct dm_target *ti)
{
	struct target_ctx *tc = (struct target_ctx *) ti->private;

	mempool_destroy (tc->bio_ctx_pool);
	mempool_destroy (tc->pg_pool);
	crypto_close (tc->ci);
	kfree(tc->volume_path);
	dm_put_device(ti, tc->dev);
	kfree(tc);
}


// Checks if two regions overlap (borders are parts of regions)
static int RegionsOverlap (u64 start1, u64 end1, u64 start2, u64 end2)
{
	return (start1 < start2) ? (end1 >= start2) : (start1 <= end2);
}


static void dereference_bio_ctx (struct bio_ctx *bc)
{
	struct target_ctx *tc = (struct target_ctx *) bc->target->private;

	if (!atomic_dec_and_test (&bc->ref_count))
		return;

	bio_endio (bc->orig_bio, bc->orig_bio->bi_size, bc->error);
	mempool_free (bc, tc->bio_ctx_pool);
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
static void work_process (struct work_struct *qdata)
{
	struct bio_ctx *bc = container_of(qdata, struct bio_ctx, work);
#else
static void work_process (void *qdata)
{
	struct bio_ctx *bc = (struct bio_ctx *) qdata;
#endif

	struct target_ctx *tc = (struct target_ctx *) bc->target->private;
	struct bio_vec *bv;
	u64 sec_no = bc->crypto_sector;
	int seg_no;
	unsigned long flags;

	// Decrypt queued data
	bio_for_each_segment (bv, bc->orig_bio, seg_no)
	{
		unsigned int secs = bv->bv_len / SECTOR_SIZE;
		char *data = bvec_kmap_irq (bv, &flags);

		DecryptSectors ((unsigned __int32 *)data, sec_no, secs, tc->ci);

		sec_no += secs;

		flush_dcache_page (bv->bv_page);
		bvec_kunmap_irq (data, &flags);

		if (seg_no + 1 < bc->orig_bio->bi_vcnt)
			cond_resched ();
	}

	dereference_bio_ctx (bc);
}


static int truecrypt_endio (struct bio *bio, unsigned int bytes_done, int error)
{
	struct bio_ctx *bc = (struct bio_ctx *) bio->bi_private;
	struct target_ctx *tc = (struct target_ctx *) bc->target->private;
	struct bio_vec *bv;
	int seg_no;
	
	trace (1, "end: sc=%llu fl=%ld rw=%ld sz=%d ix=%hd vc=%hd dn=%d er=%d\n",
		(unsigned long long) bio->bi_sector, bio->bi_flags, bio->bi_rw, bio->bi_size, bio->bi_idx, bio->bi_vcnt, bytes_done, error);

	if (error != 0)
		bc->error = error;

	if (bio->bi_size)
	{
		trace (2, "Outstanding IO: %d\n", bio->bi_size);
		return 1;
	}

	if (bio_data_dir (bio) == READ)
	{
		bio_put (bio);

		// Queue decryption to leave completion interrupt ASAP
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
		INIT_WORK (&bc->work, work_process);
#else
		INIT_WORK (&bc->work, work_process, bc);
#endif
		queue_work (work_queue, &bc->work);
		return error;
	}

	// Free pages allocated for encryption
	bio_for_each_segment (bv, bio, seg_no)
	{
		mempool_free (bv->bv_page, tc->pg_pool);  
	}

	bio_put (bio);
	dereference_bio_ctx (bc);
	return error;
}


static int truecrypt_map (struct dm_target *ti, struct bio *bio, union map_info *map_context)
{
	struct target_ctx *tc = (struct target_ctx *) ti->private;
	struct bio_ctx *bc;
	struct bio *bion;
	struct bio_vec *bv;
	int seg_no;

	trace (1, "map: sc=%llu fl=%ld rw=%ld sz=%d ix=%hd vc=%hd\n",
		(unsigned long long) bio->bi_sector, bio->bi_flags, bio->bi_rw, bio->bi_size, bio->bi_idx, bio->bi_vcnt);

	// Write protection
	if (bio_data_dir (bio) == WRITE && READ_ONLY (tc))
		return -EPERM;

	// Validate segment sizes
	bio_for_each_segment (bv, bio, seg_no)
	{
		if (bv->bv_len & (SECTOR_SIZE - 1))
		{
			error ("unsupported bio segment size %d (%ld %d %hd %hd)\n",
				bv->bv_len, bio->bi_rw, bio->bi_size, bio->bi_idx, bio->bi_vcnt);
			return -EINVAL;
		}
	}

	// Bio context
	bc = malloc_wait (tc->bio_ctx_pool, bio_data_dir (bio));
	if (!bc)
	{
		error ("bio context allocation failed\n");
		return -ENOMEM;
	}

	atomic_set (&bc->ref_count, 1);
	bc->orig_bio = bio;
	bc->error = 0;
	bc->target = ti;
	bc->crypto_sector = tc->start + (bio->bi_sector - ti->begin);

	// New bio for encrypted device
	while (!(bion = bio_alloc (GFP_NOIO | __GFP_NOMEMALLOC, bio_segments (bio))))
	{
		congestion_wait (bio_data_dir (bio), HZ / 50);
	}

	bion->bi_bdev = tc->dev->bdev;
	bion->bi_end_io = truecrypt_endio;
	bion->bi_idx = 0;
	bion->bi_private = bc;
	bion->bi_rw = bio->bi_rw;
	bion->bi_sector = bc->crypto_sector;
	bion->bi_size = bio->bi_size;
	bion->bi_vcnt = bio_segments (bio);

	if (bio_data_dir (bio) == READ)
	{
		// Buffers of originating bio can be used for decryption
		memcpy (bion->bi_io_vec,
			bio_iovec (bio),
			bion->bi_vcnt * sizeof (struct bio_vec));
	}
	else
	{
		u64 sec_no = bc->crypto_sector;
		int seg_no;

		// Encrypt data to be written
		unsigned long flags, copyFlags;
		char *data, *copy;

		memset (bion->bi_io_vec, 0, sizeof (struct bio_vec) * bion->bi_vcnt);

		bio_for_each_segment (bv, bio, seg_no)
		{
			struct bio_vec *cbv = bio_iovec_idx (bion, seg_no);
			unsigned int secs = bv->bv_len / SECTOR_SIZE;

			// Hidden volume protection
			if (!READ_ONLY (tc) && HID_VOL_PROT (tc)
				&& RegionsOverlap (sec_no, sec_no + secs - 1, tc->read_only_start, tc->read_only_end))
			{
				tc->flags |= TC_READ_ONLY | TC_PROTECTION_ACTIVATED;
			}

			if (READ_ONLY (tc))
			{
				// Write not permitted
				bio_for_each_segment (cbv, bion, seg_no)
				{
					if (cbv->bv_page != NULL)
						mempool_free (cbv->bv_page, tc->pg_pool);  
				}

				bio_put (bion);
				bc->error = READ_ONLY (tc) ? -EPERM : -ENOMEM;
				dereference_bio_ctx (bc);
				return 0;
			}

			cbv->bv_page = malloc_wait (tc->pg_pool, bio_data_dir (bion));

			cbv->bv_offset = 0;
			cbv->bv_len = bv->bv_len;

			copy = bvec_kmap_irq (cbv, &copyFlags);
			data = bvec_kmap_irq (bv, &flags);

			memcpy (copy, data, bv->bv_len);

			EncryptSectors ((unsigned __int32 *) copy, sec_no, secs, tc->ci);
			sec_no += secs;

			bvec_kunmap_irq (data, &flags);
			bvec_kunmap_irq (copy, &copyFlags);
			flush_dcache_page (bv->bv_page);
			flush_dcache_page (cbv->bv_page);

			if (seg_no + 1 < bio->bi_vcnt)
				cond_resched();
		}
	}

	atomic_inc (&bc->ref_count);
	generic_make_request (bion);

	dereference_bio_ctx (bc);
	return 0;
}


static int truecrypt_status (struct dm_target *ti, status_type_t type, char *result, unsigned int maxlen)
{
	struct target_ctx *tc = (struct target_ctx *) ti->private;

	switch (type)
	{
	case STATUSTYPE_INFO:
		result[0] = 0;
		break;

	case STATUSTYPE_TABLE:
		{
			char name[32];
			format_dev_t (name, tc->dev->bdev->bd_dev);
			snprintf (result, maxlen, "%d %d 0 0 %s %llu %llu %llu %llu %llu %llu %d %s",
				tc->ci->ea,
				tc->ci->mode,
				name,
				(unsigned long long) tc->start,
				tc->read_only_start,
				tc->read_only_end,
				tc->uid,
				tc->mtime,
				tc->atime,
				tc->flags,
				tc->volume_path);
		}
		break;
	}

	return 0;
}


static struct target_type truecrypt_target = {
	.name   = "truecrypt",
	.version= {TC_VERSION_NUM1, TC_VERSION_NUM2, TC_VERSION_NUM3},
	.module = THIS_MODULE,
	.ctr    = truecrypt_ctr,
	.dtr    = truecrypt_dtr,
	.map    = truecrypt_map,
	.status = truecrypt_status
};


int __init dm_truecrypt_init(void)
{
	int r;

	if (!AutoTestAlgorithms ())
	{
		error ("self-test of algorithms failed");
		return -ERANGE;
	}

	work_queue = create_workqueue ("truecryptq");

	if (!work_queue)
	{
		error ("create_workqueue failed");
		goto err;
	}

	bio_ctx_cache = kmem_cache_create ("truecrypt-bioctx", sizeof (struct bio_ctx), 0, 0, NULL, NULL);
	if (!bio_ctx_cache)
	{
		error ("kmem_cache_create failed");
		goto err;
	}

	r = dm_register_target (&truecrypt_target);
	if (r < 0)
	{
		error ("register failed %d", r);
		goto err;
	}

	return r;

err:
	if (work_queue)
		destroy_workqueue (work_queue);
	if (bio_ctx_cache)
		kmem_cache_destroy (bio_ctx_cache);

	return -ENOMEM;
}


void __exit dm_truecrypt_exit(void)
{
	int r;

	r = dm_unregister_target (&truecrypt_target);

	if (r < 0)
		error ("unregister failed %d", r);

	destroy_workqueue (work_queue);
	kmem_cache_destroy (bio_ctx_cache);
}


module_init(dm_truecrypt_init);
module_exit(dm_truecrypt_exit);
module_param_named(trace, trace_level, int, 0);

MODULE_AUTHOR("TrueCrypt Foundation");
MODULE_DESCRIPTION("device-mapper target for encryption and decryption of TrueCrypt volumes");
MODULE_PARM_DESC(trace, "Trace level");
MODULE_LICENSE("GPL and additional rights");
