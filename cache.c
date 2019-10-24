// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  linux/fs/fat/cache.c
 *
 *  Written 1992,1993 by Werner Almesberger
 *
 *  Mar 1999. AV. Changed cache, so that it uses the starting cluster instead
 *	of inode number.
 *  May 1999. AV. Fixed the bogosity with FAT32 (read "FAT28"). Fscking lusers.
 *  Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/slab.h>
#include <asm/unaligned.h>
#include <linux/buffer_head.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

#define EXTENT_CACHE_VALID	0
#define EXTENT_MAX_CACHE	16

struct exfat_cache {
	struct list_head cache_list;
	unsigned int nr_contig;	/* number of contiguous clusters */
	unsigned int fcluster;	/* cluster number in the file. */
	unsigned int dcluster;	/* cluster number on disk. */
};

struct exfat_cache_id {
	unsigned int id;
	unsigned int nr_contig;
	unsigned int fcluster;
	unsigned int dcluster;
};

static struct kmem_cache *exfat_cachep;

static void init_once(void *c)
{
	struct exfat_cache *cache = (struct exfat_cache *)c;

	INIT_LIST_HEAD(&cache->cache_list);
}

int exfat_cache_init(void)
{
	exfat_cachep = kmem_cache_create("exfat_cache",
				sizeof(struct exfat_cache),
				0, SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD,
				init_once);
	if (!exfat_cachep)
		return -ENOMEM;
	return 0;
}

void exfat_cache_shutdown(void)
{
	if (!exfat_cachep)
		return;
	kmem_cache_destroy(exfat_cachep);
}

void exfat_cache_init_inode(struct inode *inode)
{
	struct exfat_file_id *fid = EXFAT_I(inode)->fid;

	spin_lock_init(&fid->cache_lru_lock);
	fid->nr_caches = 0;
	fid->cache_valid_id = EXTENT_CACHE_VALID + 1;
	INIT_LIST_HEAD(&fid->cache_lru);
}

static inline struct exfat_cache *exfat_cache_alloc(void)
{
	return kmem_cache_alloc(exfat_cachep, GFP_NOFS);
}

static inline void exfat_cache_free(struct exfat_cache *cache)
{
	WARN_ON(!list_empty(&cache->cache_list));
	kmem_cache_free(exfat_cachep, cache);
}

static inline void exfat_cache_update_lru(struct inode *inode,
		struct exfat_cache *cache)
{
	struct exfat_file_id *fid = EXFAT_I(inode)->fid;

	if (fid->cache_lru.next != &cache->cache_list)
		list_move(&cache->cache_list, &fid->cache_lru);
}

static unsigned int exfat_cache_lookup(struct inode *inode,
		unsigned int fclus, struct exfat_cache_id *cid,
		unsigned int *cached_fclus, unsigned int *cached_dclus)
{
	struct exfat_file_id *fid = EXFAT_I(inode)->fid;
	static struct exfat_cache nohit = { .fcluster = 0, };
	struct exfat_cache *hit = &nohit, *p;
	unsigned int offset = CLUS_EOF;

	spin_lock(&fid->cache_lru_lock);
	list_for_each_entry(p, &fid->cache_lru, cache_list) {
		/* Find the cache of "fclus" or nearest cache. */
		if (p->fcluster <= fclus && hit->fcluster < p->fcluster) {
			hit = p;
			if ((hit->fcluster + hit->nr_contig) < fclus) {
				offset = hit->nr_contig;
			} else {
				offset = fclus - hit->fcluster;
				break;
			}
		}
	}
	if (hit != &nohit) {
		exfat_cache_update_lru(inode, hit);

		cid->id = fid->cache_valid_id;
		cid->nr_contig = hit->nr_contig;
		cid->fcluster = hit->fcluster;
		cid->dcluster = hit->dcluster;
		*cached_fclus = cid->fcluster + offset;
		*cached_dclus = cid->dcluster + offset;
	}
	spin_unlock(&fid->cache_lru_lock);

	return offset;
}

static struct exfat_cache *exfat_cache_merge(struct inode *inode,
		struct exfat_cache_id *new)
{
	struct exfat_file_id *fid = EXFAT_I(inode)->fid;
	struct exfat_cache *p;

	list_for_each_entry(p, &fid->cache_lru, cache_list) {
		/* Find the same part as "new" in cluster-chain. */
		if (p->fcluster == new->fcluster) {
			if (new->nr_contig > p->nr_contig)
				p->nr_contig = new->nr_contig;
			return p;
		}
	}
	return NULL;
}

static void exfat_cache_add(struct inode *inode,
		struct exfat_cache_id *new)
{
	struct exfat_file_id *fid = EXFAT_I(inode)->fid;
	struct exfat_cache *cache, *tmp;

	if (new->fcluster == -1) /* dummy cache */
		return;

	spin_lock(&fid->cache_lru_lock);
	if (new->id != EXTENT_CACHE_VALID &&
	    new->id != fid->cache_valid_id)
		goto out;	/* this cache was invalidated */

	cache = exfat_cache_merge(inode, new);
	if (cache == NULL) {
		if (fid->nr_caches < EXTENT_MAX_CACHE) {
			fid->nr_caches++;
			spin_unlock(&fid->cache_lru_lock);

			tmp = exfat_cache_alloc();
			if (!tmp) {
				spin_lock(&fid->cache_lru_lock);
				fid->nr_caches--;
				spin_unlock(&fid->cache_lru_lock);
				return;
			}

			spin_lock(&fid->cache_lru_lock);
			cache = exfat_cache_merge(inode, new);
			if (cache != NULL) {
				fid->nr_caches--;
				exfat_cache_free(tmp);
				goto out_update_lru;
			}
			cache = tmp;
		} else {
			struct list_head *p = fid->cache_lru.prev;

			cache = list_entry(p,
					struct exfat_cache, cache_list);
		}
		cache->fcluster = new->fcluster;
		cache->dcluster = new->dcluster;
		cache->nr_contig = new->nr_contig;
	}
out_update_lru:
	exfat_cache_update_lru(inode, cache);
out:
	spin_unlock(&fid->cache_lru_lock);
}

/*
 * Cache invalidation occurs rarely, thus the LRU chain is not updated. It
 * fixes itself after a while.
 */
static void __exfat_cache_inval_inode(struct inode *inode)
{
	struct exfat_file_id *fid = EXFAT_I(inode)->fid;
	struct exfat_cache *cache;

	while (!list_empty(&fid->cache_lru)) {
		cache = list_entry(fid->cache_lru.next,
				   struct exfat_cache, cache_list);
		list_del_init(&cache->cache_list);
		fid->nr_caches--;
		exfat_cache_free(cache);
	}
	/* Update. The copy of caches before this id is discarded. */
	fid->cache_valid_id++;
	if (fid->cache_valid_id == EXTENT_CACHE_VALID)
		fid->cache_valid_id++;
}

void exfat_cache_inval_inode(struct inode *inode)
{
	struct exfat_file_id *fid = EXFAT_I(inode)->fid;

	spin_lock(&fid->cache_lru_lock);
	__exfat_cache_inval_inode(inode);
	spin_unlock(&fid->cache_lru_lock);
}

static inline int cache_contiguous(struct exfat_cache_id *cid,
		unsigned int dclus)
{
	cid->nr_contig++;
	return ((cid->dcluster + cid->nr_contig) == dclus);
}

static inline void cache_init(struct exfat_cache_id *cid,
		unsigned int fclus, unsigned int dclus)
{
	cid->id = EXTENT_CACHE_VALID;
	cid->fcluster = fclus;
	cid->dcluster = dclus;
	cid->nr_contig = 0;
}

int exfat_get_clus(struct inode *inode, unsigned int cluster,
		unsigned int *fclus, unsigned int *dclus,
		unsigned int *last_dclus, int allow_eof)
{
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int limit = sbi->num_clusters;
	struct exfat_file_id *fid = EXFAT_I(inode)->fid;
	struct exfat_cache_id cid;
	unsigned int content;

	if (IS_CLUS_FREE(fid->start_clu)) {
		exfat_fs_error(sb,
			"invalid access to exfat cache (entry 0x%08x)",
			fid->start_clu);
		return -EIO;
	}

	*fclus = 0;
	*dclus = fid->start_clu;
	*last_dclus = *dclus;

	/*
	 * Don`t use exfat_cache if zero offset or non-cluster allocation
	 */
	if ((cluster == 0) || IS_CLUS_EOF(*dclus))
		return 0;

	cache_init(&cid, CLUS_EOF, CLUS_EOF);

	if (exfat_cache_lookup(inode, cluster, &cid, fclus, dclus) ==
		CLUS_EOF) {
		/*
		 * dummy, always not contiguous
		 * This is reinitialized by cache_init(), later.
		 */
		WARN_ON((cid.id != EXTENT_CACHE_VALID)
			|| (cid.fcluster != CLUS_EOF)
			|| (cid.dcluster != CLUS_EOF)
			|| (cid.nr_contig != 0));
	}

	if (*fclus == cluster)
		return 0;

	while (*fclus < cluster) {
		/* prevent the infinite loop of cluster chain */
		if (*fclus > limit) {
			exfat_fs_error(sb,
				"detected the cluster chain loop (i_pos %u)",
				(*fclus));
			return -EIO;
		}

		if (exfat_ent_get_safe(sb, *dclus, &content))
			return -EIO;

		*last_dclus = *dclus;
		*dclus = content;
		(*fclus)++;

		if (IS_CLUS_EOF(content)) {
			if (!allow_eof) {
				exfat_fs_error(sb,
				       "invalid cluster chain (i_pos %u, last_clus 0x%08x is EOF)",
				       *fclus, (*last_dclus));
				return -EIO;
			}

			break;
		}

		if (!cache_contiguous(&cid, *dclus))
			cache_init(&cid, *fclus, *dclus);
	}

	exfat_cache_add(inode, &cid);
	return 0;
}
