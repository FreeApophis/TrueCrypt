/* 
Copyright (c) 2004-2006 TrueCrypt Foundation. All rights reserved. 

Covered by TrueCrypt License 2.0 the full text of which is contained in the file
License.txt included in TrueCrypt binary and source code distribution archives. 
*/

#include <linux/bio.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include "dm.h"

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

struct target_ctx
{
	struct dm_dev *dev;
	sector_t start;
	char *volume_path;
	mempool_t *bio_ctx_pool;
	mempool_t *pg_pool;
	sector_t read_only_start;
	sector_t read_only_end;
	u64 mtime;
	u64 atime;
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
static kmem_cache_t *bio_ctx_cache = NULL;

#define READ_ONLY(tc) (tc->flags & FLAG_READ_ONLY)
#define HID_VOL_PROT(tc) (tc->flags & FLAG_HIDDEN_VOLUME_PROTECTION)


static int hex2bin (char *hex_string, u8 *byte_buf, int max_length)
{
	int i = 0, n;
	char s[3];
	s[2] = 0;

	trace (3, "hex2bin (%p, %p, %d)\n", hex_string, byte_buf, max_length);

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
static void *mempool_alloc_pg (unsigned int gfp_mask, void *pool_data)
#else
static void *mempool_alloc_pg (int gfp_mask, void *pool_data)
#endif
{
	trace (3, "mempool_alloc_pg (%d, %p)\n", gfp_mask, pool_data);
	return alloc_page (gfp_mask);
}


static void mempool_free_pg (void *element, void *pool_data)
{
	trace (3, "mempool_free_pg (%p, %p)\n", element, pool_data);
	__free_page (element);
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

	trace (3, "truecrypt_ctr (%p, %d, %p)\n", ti, argc, argv);

	if (argc != LAST_ARG + 1)
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

	tc->bio_ctx_pool = mempool_create (MIN_POOL_SIZE, mempool_alloc_slab, mempool_free_slab, bio_ctx_cache);
	if (!tc->bio_ctx_pool)
	{
		ti->error = "truecrypt: Cannot create bio context memory pool";
		error = -ENOMEM;
		goto err;
	}

	tc->pg_pool = mempool_create (MIN_POOL_SIZE, mempool_alloc_pg, mempool_free_pg, NULL);
	if (!tc->pg_pool)
	{
		ti->error = "truecrypt: Cannot create page memory pool";
		error = -ENOMEM;
		goto err;
	}

	if (sscanf (argv[ARG_SEC], SECTOR_FORMAT, &tc->start) != 1)
	{
		ti->error = "truecrypt: Invalid device sector";
		goto err;
	}

	if (dm_get_device (ti, argv[ARG_DEV], tc->start, ti->len, dm_table_get_mode (ti->table), &tc->dev))
	{
		ti->error = "truecrypt: Device lookup failed";
		goto err;
	}

	// Encryption algorithm
	tc->ci->ea = 0;
	if (sscanf (argv[ARG_EA], "%d", &tc->ci->ea) != 1
		|| tc->ci->ea < EAGetFirst ()
		|| tc->ci->ea > EAGetCount ())
	{
		ti->error = "truecrypt: Invalid encryption algorithm";
		goto err;
	}

	// Mode of operation
	tc->ci->mode = 0;
	if (sscanf (argv[ARG_MODE], "%d", &tc->ci->mode) != 1
		|| tc->ci->mode < 1
		|| tc->ci->mode >= INVALID_MODE)
	{
		ti->error = "truecrypt: Invalid mode of operation";
		goto err;
	}

	// Key
	key_size = EAGetKeySize (tc->ci->ea);
	if (hex2bin (argv[ARG_KEY], tc->ci->master_key, key_size) != key_size)
	{
		ti->error = "truecrypt: Invalid key";
		goto err;
	}
	
	// EA init
	trace (2, "EAInit (%d, %p, %p)\n", tc->ci->ea, tc->ci->master_key, tc->ci->ks);
	if (EAInit (tc->ci->ea, tc->ci->master_key, tc->ci->ks) == ERR_CIPHER_INIT_FAILURE)
	{
		ti->error = "truecrypt: Encryption algorithm initialization failed";
		goto err;
	}

	// Key2 / IV
	if (hex2bin (argv[ARG_IV], tc->ci->iv, sizeof (tc->ci->iv)) != sizeof (tc->ci->iv))
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
	if (sscanf (argv[ARG_RO_START], SECTOR_FORMAT, &tc->read_only_start) != 1)
	{
		ti->error = "truecrypt: Invalid read-only start sector";
		goto err;
	}

	// Read-only end sector
	if (sscanf (argv[ARG_RO_END], SECTOR_FORMAT, &tc->read_only_end) != 1)
	{
		ti->error = "truecrypt: Invalid read-only end sector";
		goto err;
	}

	// Modification time
	if (sscanf (argv[ARG_MTIME], "%Ld", &tc->mtime) != 1)
	{
		ti->error = "truecrypt: Invalid modification time";
		goto err;
	}

	// Access time
	if (sscanf (argv[ARG_ATIME], "%Ld", &tc->atime) != 1)
	{
		ti->error = "truecrypt: Invalid access time";
		goto err;
	}

	// Flags
	if (sscanf (argv[ARG_FLAGS], "%d", &tc->flags) != 1)
	{
		ti->error = "truecrypt: Invalid flags";
		goto err;
	}

	// Volume path
	tc->volume_path = kmalloc (strlen (argv[ARG_VOL]) + 1, GFP_KERNEL);
	if (tc->volume_path == NULL)
	{
		ti->error = "truecrypt: Cannot allocate volume path buffer";
		error = -ENOMEM;
		goto err;
	}
	strcpy (tc->volume_path, argv[ARG_VOL]);

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
	trace (3, "truecrypt_ctr: error\n");

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

	trace (3, "truecrypt_dtr (%p)\n", ti);

	mempool_destroy (tc->bio_ctx_pool);
	mempool_destroy (tc->pg_pool);
	crypto_close (tc->ci);
	kfree(tc->volume_path);
	dm_put_device(ti, tc->dev);
	kfree(tc);
}


// Checks if two regions overlap (borders are parts of regions)
static int RegionsOverlap (sector_t start1, sector_t end1, sector_t start2, sector_t end2)
{
	return (start1 < start2) ? (end1 >= start2) : (start1 <= end2);
}


static void dereference_bio_ctx (struct bio_ctx *bc)
{
	struct target_ctx *tc = (struct target_ctx *) bc->target->private;
	trace (3, "dereference_bio_ctx (%p)\n", bc);

	if (!atomic_dec_and_test (&bc->ref_count))
		return;

	bio_endio (bc->orig_bio, bc->orig_bio->bi_size, bc->error);
	trace (3, "dereference_bio_ctx: mempool_free (%p)\n", bc);
	mempool_free (bc, tc->bio_ctx_pool);
}


static void work_process (void *data)
{
	struct bio_ctx *bc = (struct bio_ctx *) data;
	struct target_ctx *tc = (struct target_ctx *) bc->target->private;
	struct bio_vec *bv;
	sector_t sec_no = bc->crypto_sector;
	int seg_no;
	unsigned long flags;

	trace (3, "work_process (%p)\n", data);

	// Decrypt queued data
	bio_for_each_segment (bv, bc->orig_bio, seg_no)
	{
		unsigned int secs = bv->bv_len / SECTOR_SIZE;
		char *data = bvec_kmap_irq (bv, &flags);

		trace (2, "DecryptSectors (%Ld, %d)\n", sec_no, secs);
		DecryptSectors ((unsigned __int32 *)data, sec_no, secs, tc->ci);

		sec_no += secs;

		flush_dcache_page (bv->bv_page);
		bvec_kunmap_irq (data, &flags);
	}

	dereference_bio_ctx (bc);
}


static int truecrypt_endio (struct bio *bio, unsigned int bytes_done, int error)
{
	struct bio_ctx *bc = (struct bio_ctx *) bio->bi_private;
	struct target_ctx *tc = (struct target_ctx *) bc->target->private;
	struct bio_vec *bv;
	int seg_no;
	
	trace (3, "truecrypt_endio (%p, %d, %d)\n", bio, bytes_done, error);
	trace (1, "end: sc=" SECTOR_FORMAT " fl=%ld rw=%ld sz=%d ix=%hd vc=%hd dn=%d er=%d\n",
		bio->bi_sector, bio->bi_flags, bio->bi_rw, bio->bi_size, bio->bi_idx, bio->bi_vcnt, bytes_done, error);

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
		INIT_WORK (&bc->work, work_process, bc);
		trace (3, "queue_work (%p)\n", work_queue);
		queue_work (work_queue, &bc->work);
		return error;
	}

	// Free pages allocated for encryption
	bio_for_each_segment (bv, bio, seg_no)
	{
		trace (3, "mempool_free (%p, %p)\n", bv->bv_page, tc->pg_pool);
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

	trace (3, "truecrypt_map (%p, %p, %p)\n", ti, bio, map_context);
	trace (1, "map: sc=" SECTOR_FORMAT " fl=%ld rw=%ld sz=%d ix=%hd vc=%hd\n",
		bio->bi_sector, bio->bi_flags, bio->bi_rw, bio->bi_size, bio->bi_idx, bio->bi_vcnt);

	// Write protection
	if (bio_data_dir (bio) == WRITE && READ_ONLY (tc))
		return -EPERM;

	// Validate segment sizes
	bio_for_each_segment (bv, bio, seg_no)
	{
		if (bv->bv_len & (SECTOR_SIZE - 1))
		{
			error ("unsupported segment size %d (%ld %d %hd %hd)\n",
				bv->bv_len, bio->bi_rw, bio->bi_size, bio->bi_idx, bio->bi_vcnt);
			return -EINVAL;
		}
	}

	// Bio context
	bc = mempool_alloc (tc->bio_ctx_pool, GFP_NOIO);
	if (!bc)
	{
		error ("bio context allocation failed\n");
		return -ENOMEM;
	}
	trace (3, "truecrypt_map: mempool_alloc bc: %p\n", bc);

	atomic_set (&bc->ref_count, 1);
	bc->orig_bio = bio;
	bc->error = 0;
	bc->target = ti;
	bc->crypto_sector = tc->start + (bio->bi_sector - ti->begin);

	// New bio for encrypted device
	trace (3, "bio_alloc (%hd)\n", bio_segments (bio));
	bion = bio_alloc (GFP_NOIO, bio_segments (bio));
	if (!bion) 
	{
		error ("bio allocation failed\n");
		bc->error = -ENOMEM;
		dereference_bio_ctx (bc);
		return 0;
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
		// Encrypt data to be written
		unsigned long flags, copyFlags;
		char *data, *copy;
		long long sec_no = bc->crypto_sector;

		memset (bion->bi_io_vec, 0, sizeof (struct bio_vec) * bion->bi_vcnt);

		bio_for_each_segment (bv, bio, seg_no)
		{
			struct bio_vec *cbv = bio_iovec_idx (bion, seg_no);
			unsigned int secs = bv->bv_len / SECTOR_SIZE;

			// Hidden volume protection
			if (!READ_ONLY (tc) && HID_VOL_PROT (tc)
				&& RegionsOverlap (sec_no, sec_no + secs - 1, tc->read_only_start, tc->read_only_end))
			{
				tc->flags |= FLAG_READ_ONLY | FLAG_PROTECTION_ACTIVATED;
			}

			if (!READ_ONLY (tc))
			{
				cbv->bv_page = mempool_alloc (tc->pg_pool, GFP_NOIO);
				if (cbv->bv_page == NULL)
					error ("page allocation failed during write\n");
			}

			if (READ_ONLY (tc) || cbv->bv_page == NULL)
			{
				// Write not permitted or no memory
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
			trace (3, "truecrypt_map: mempool_alloc pg: %p\n", cbv->bv_page);

			cbv->bv_offset = 0;
			cbv->bv_len = bv->bv_len;

			copy = bvec_kmap_irq (cbv, &copyFlags);
			data = bvec_kmap_irq (bv, &flags);

			memcpy (copy, data, bv->bv_len);

			flush_dcache_page (bv->bv_page);
			bvec_kunmap_irq (data, &flags);

			trace (2, "EncryptSectors (%Ld, %d)\n", sec_no, secs);

			EncryptSectors ((unsigned __int32 *)copy, sec_no, secs, tc->ci);
			sec_no += secs;

			flush_dcache_page (cbv->bv_page);
			bvec_kunmap_irq (copy, &copyFlags);
		}
	}

	atomic_inc (&bc->ref_count);

	trace (3, "generic_make_request (rw=%ld sc=" SECTOR_FORMAT ")\n", bion->bi_rw, bion->bi_sector);
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
			snprintf (result, maxlen, "%d %d 0 0 %s " SECTOR_FORMAT " " SECTOR_FORMAT " " SECTOR_FORMAT " %Ld %Ld %d %s",
				tc->ci->ea,
				tc->ci->mode,
				name,
				tc->start,
				tc->read_only_start,
				tc->read_only_end,
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
	.version= {VERSION_NUM1, VERSION_NUM2, VERSION_NUM3},
	.module = THIS_MODULE,
	.ctr    = truecrypt_ctr,
	.dtr    = truecrypt_dtr,
	.map    = truecrypt_map,
	.status = truecrypt_status
};


int __init dm_truecrypt_init(void)
{
	int r;
	trace (3, "dm_truecrypt_init (trace_level=%d)\n", trace_level);

	if (!AutoTestAlgorithms ())
	{
		DMERR ("truecrypt: self-test of algorithms failed");
		return -ERANGE;
	}

	work_queue = create_workqueue ("truecryptq");

	if (!work_queue)
	{
		DMERR ("truecrypt: create_workqueue creation failed");
		goto err;
	}

	bio_ctx_cache = kmem_cache_create ("truecrypt-bioctx", sizeof (struct bio_ctx), 0, 0, NULL, NULL);
	if (!bio_ctx_cache)
	{
		DMERR ("truecrypt: kmem_cache_create failed");
		goto err;
	}

	r = dm_register_target (&truecrypt_target);
	if (r < 0)
	{
		DMERR ("truecrypt: register failed %d", r);
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
	trace (3, "dm_truecrypt_exit ()\n");

	r = dm_unregister_target (&truecrypt_target);

	if (r < 0)
		DMERR ("truecrypt: unregister failed %d", r);

	destroy_workqueue (work_queue);
	kmem_cache_destroy (bio_ctx_cache);
}


module_init(dm_truecrypt_init);
module_exit(dm_truecrypt_exit);
module_param_named(trace, trace_level, int, 0);

MODULE_AUTHOR("TrueCrypt Foundation");
MODULE_DESCRIPTION(DM_NAME " target for encryption and decryption of TrueCrypt volumes");
MODULE_PARM_DESC(trace, "Trace level");
MODULE_LICENSE("GPL and additional rights"); // Kernel thinks only GPL/BSD/MPL != closed-source code
