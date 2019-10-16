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

#include "exfat_raw.h"
#include "exfat_fs.h"

#define EXTENT_CACHE_VALID	0
#define EXTENT_MAX_CACHE	16

struct exfat_cluster_cache {
	struct list_head cache_list;
	unsigned int nr_contig;	/* number of contiguous clusters */
	unsigned int fcluster;	/* cluster number in the file. */
	unsigned int dcluster;	/* cluster number on disk. */
};

struct exfat_cluster_cache_id {
	unsigned int id;
	unsigned int nr_contig;
	unsigned int fcluster;
	unsigned int dcluster;
};

static struct kmem_cache *exfat_cluster_cachep;

static void init_once(void *c)
{
	struct exfat_cluster_cache *cache = (struct exfat_cluster_cache *)c;

	INIT_LIST_HEAD(&cache->cache_list);
}

int exfat_cluster_cache_init(void)
{
	exfat_cluster_cachep = kmem_cache_create("exfat_cluster_cache",
				sizeof(struct exfat_cluster_cache),
				0, SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD,
				init_once);
	if (!exfat_cluster_cachep)
		return -ENOMEM;
	return 0;
}

void exfat_cluster_cache_shutdown(void)
{
	if (!exfat_cluster_cachep)
		return;
	kmem_cache_destroy(exfat_cluster_cachep);
}

void exfat_cluster_cache_init_inode(struct inode *inode)
{
	struct exfat_cluster_cache_lru *exfat_lru = &(EXFAT_I(inode)->fid.exfat_lru);

	spin_lock_init(&exfat_lru->cache_lru_lock);
	exfat_lru->nr_caches = 0;
	exfat_lru->cache_valid_id = EXTENT_CACHE_VALID + 1;
	INIT_LIST_HEAD(&exfat_lru->cache_lru);
}

static inline struct exfat_cluster_cache *exfat_cluster_cache_alloc(void)
{
	return kmem_cache_alloc(exfat_cluster_cachep, GFP_NOFS);
}

static inline void exfat_cluster_cache_free(struct exfat_cluster_cache *cache)
{
	WARN_ON(!list_empty(&cache->cache_list));
	kmem_cache_free(exfat_cluster_cachep, cache);
}

static inline void exfat_cluster_cache_update_lru(struct inode *inode,
					struct exfat_cluster_cache *cache)
{
	struct exfat_cluster_cache_lru *exfat_lru = &(EXFAT_I(inode)->fid.exfat_lru);

	if (exfat_lru->cache_lru.next != &cache->cache_list)
		list_move(&cache->cache_list, &exfat_lru->cache_lru);
}

static unsigned int exfat_cluster_cache_lookup(struct inode *inode, unsigned int fclus,
	struct exfat_cluster_cache_id *cid, unsigned int *cached_fclus,
	unsigned int *cached_dclus)
{
	struct exfat_cluster_cache_lru *exfat_lru = &(EXFAT_I(inode)->fid.exfat_lru);

	static struct exfat_cluster_cache nohit = { .fcluster = 0, };

	struct exfat_cluster_cache *hit = &nohit, *p;
	unsigned int offset = CLUS_EOF;

	spin_lock(&exfat_lru->cache_lru_lock);
	list_for_each_entry(p, &exfat_lru->cache_lru, cache_list) {
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
		exfat_cluster_cache_update_lru(inode, hit);

		cid->id = exfat_lru->cache_valid_id;
		cid->nr_contig = hit->nr_contig;
		cid->fcluster = hit->fcluster;
		cid->dcluster = hit->dcluster;
		*cached_fclus = cid->fcluster + offset;
		*cached_dclus = cid->dcluster + offset;
	}
	spin_unlock(&exfat_lru->cache_lru_lock);

	return offset;
}

static struct exfat_cluster_cache *exfat_cluster_cache_merge(struct inode *inode,
					 struct exfat_cluster_cache_id *new)
{
	struct exfat_cluster_cache_lru *exfat_lru = &(EXFAT_I(inode)->fid.exfat_lru);
	struct exfat_cluster_cache *p;

	list_for_each_entry(p, &exfat_lru->cache_lru, cache_list) {
		/* Find the same part as "new" in cluster-chain. */
		if (p->fcluster == new->fcluster) {
			if (new->nr_contig > p->nr_contig)
				p->nr_contig = new->nr_contig;
			return p;
		}
	}
	return NULL;
}

static void exfat_cluster_cache_add(struct inode *inode, struct exfat_cluster_cache_id *new)
{
	struct exfat_cluster_cache_lru *exfat_lru = &(EXFAT_I(inode)->fid.exfat_lru);
	struct exfat_cluster_cache *cache, *tmp;

	if (new->fcluster == -1) /* dummy cache */
		return;

	spin_lock(&exfat_lru->cache_lru_lock);
	if (new->id != EXTENT_CACHE_VALID &&
	    new->id != exfat_lru->cache_valid_id)
		goto out;	/* this cache was invalidated */

	cache = exfat_cluster_cache_merge(inode, new);
	if (cache == NULL) {
		if (exfat_lru->nr_caches < EXTENT_MAX_CACHE) {
			exfat_lru->nr_caches++;
			spin_unlock(&exfat_lru->cache_lru_lock);

			tmp = exfat_cluster_cache_alloc();
			if (!tmp) {
				spin_lock(&exfat_lru->cache_lru_lock);
				exfat_lru->nr_caches--;
				spin_unlock(&exfat_lru->cache_lru_lock);
				return;
			}

			spin_lock(&exfat_lru->cache_lru_lock);
			cache = exfat_cluster_cache_merge(inode, new);
			if (cache != NULL) {
				exfat_lru->nr_caches--;
				exfat_cluster_cache_free(tmp);
				goto out_update_lru;
			}
			cache = tmp;
		} else {
			struct list_head *p = exfat_lru->cache_lru.prev;

			cache = list_entry(p, struct exfat_cluster_cache, cache_list);
		}
		cache->fcluster = new->fcluster;
		cache->dcluster = new->dcluster;
		cache->nr_contig = new->nr_contig;
	}
out_update_lru:
	exfat_cluster_cache_update_lru(inode, cache);
out:
	spin_unlock(&exfat_lru->cache_lru_lock);
}

/*
 * Cache invalidation occurs rarely, thus the LRU chain is not updated. It
 * fixes itself after a while.
 */
static void __exfat_cluster_cache_inval_inode(struct inode *inode)
{
	struct exfat_cluster_cache_lru *exfat_lru = &(EXFAT_I(inode)->fid.exfat_lru);
	struct exfat_cluster_cache *cache;

	while (!list_empty(&exfat_lru->cache_lru)) {
		cache = list_entry(exfat_lru->cache_lru.next,
				   struct exfat_cluster_cache, cache_list);
		list_del_init(&cache->cache_list);
		exfat_lru->nr_caches--;
		exfat_cluster_cache_free(cache);
	}
	/* Update. The copy of caches before this id is discarded. */
	exfat_lru->cache_valid_id++;
	if (exfat_lru->cache_valid_id == EXTENT_CACHE_VALID)
		exfat_lru->cache_valid_id++;
}

void exfat_cluster_cache_inval_inode(struct inode *inode)
{
	struct exfat_cluster_cache_lru *exfat_lru = &(EXFAT_I(inode)->fid.exfat_lru);

	spin_lock(&exfat_lru->cache_lru_lock);
	__exfat_cluster_cache_inval_inode(inode);
	spin_unlock(&exfat_lru->cache_lru_lock);
}

static inline int cache_contiguous(struct exfat_cluster_cache_id *cid,
	unsigned int dclus)
{
	cid->nr_contig++;
	return ((cid->dcluster + cid->nr_contig) == dclus);
}

static inline void cache_init(struct exfat_cluster_cache_id *cid, unsigned int fclus,
	unsigned int dclus)
{
	cid->id = EXTENT_CACHE_VALID;
	cid->fcluster = fclus;
	cid->dcluster = dclus;
	cid->nr_contig = 0;
}

int exfat_get_clus(struct inode *inode, unsigned int cluster,
	unsigned int *fclus, unsigned int *dclus, unsigned int *last_dclus,
	int allow_eof)
{
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int limit = sbi->num_clusters;
	struct exfat_file_id *fid = &(EXFAT_I(inode)->fid);
	struct exfat_cluster_cache_id cid;
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
	 * Don`t use exfat_cluster_cache if zero offset or non-cluster allocation
	 */
	if ((cluster == 0) || IS_CLUS_EOF(*dclus))
		return 0;

	cache_init(&cid, CLUS_EOF, CLUS_EOF);

	if (exfat_cluster_cache_lookup(inode, cluster, &cid, fclus, dclus) ==
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

	exfat_cluster_cache_add(inode, &cid);
	return 0;
}

#define LOCKBIT         (0x01)

static void exfat_push_to_mru(struct exfat_meta_cache *bp, struct exfat_meta_cache *list)
{
	bp->next = list->next;
	bp->prev = list;
	list->next->prev = bp;
	list->next = bp;
}

static void exfat_push_to_lru(struct exfat_meta_cache *bp, struct exfat_meta_cache *list)
{
	bp->prev = list->prev;
	bp->next = list;
	list->prev->next = bp;
	list->prev = bp;
}

static void exfat_move_to_mru(struct exfat_meta_cache *bp, struct exfat_meta_cache *list)
{
	bp->prev->next = bp->next;
	bp->next->prev = bp->prev;
	exfat_push_to_mru(bp, list);
}

static void exfat_move_to_lru(struct exfat_meta_cache *bp, struct exfat_meta_cache *list)
{
	bp->prev->next = bp->next;
	bp->next->prev = bp->prev;
	exfat_push_to_lru(bp, list);
}

static inline bool exfat_check_hash_valid(struct exfat_meta_cache *bp)
{
	if ((bp->hash.next == bp) || (bp->hash.prev == bp))
		return true;

	return false;
}

static inline void exfat_remove_from_hash(struct exfat_meta_cache *bp)
{
	(bp->hash.prev)->hash.next = bp->hash.next;
	(bp->hash.next)->hash.prev = bp->hash.prev;
	bp->hash.next = bp;
	bp->hash.prev = bp;
}

static struct exfat_meta_cache *exfat_find_dcache(struct super_block *sb,
		unsigned long long sec)
{
	int off;
	struct exfat_meta_cache *bp, *hp;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	off = (sec + (sec >> sbi->sect_per_clus_bits)) &
		(BUF_CACHE_HASH_SIZE - 1);

	hp = &(sbi->dcache.hash_list[off]);
	for (bp = hp->hash.next; bp != hp; bp = bp->hash.next) {
		if (bp->sec == sec) {
			touch_buffer(bp->bh);
			return bp;
		}
	}
	return NULL;
}

static struct exfat_meta_cache *exfat_get_dcache(struct super_block *sb)
{
	struct exfat_meta_cache *bp;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	bp = sbi->dcache.lru_list.prev;
	while (bp->flag & LOCKBIT)
		bp = bp->prev;

	exfat_move_to_mru(bp, &sbi->dcache.lru_list);
	return bp;
}

static void exfat_insert_dcache_hash(struct super_block *sb, struct exfat_meta_cache *bp)
{
	int off;
	struct exfat_meta_cache *hp;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	off = (bp->sec + (bp->sec >> sbi->sect_per_clus_bits)) &
		(BUF_CACHE_HASH_SIZE-1);

	hp = &(sbi->dcache.hash_list[off]);
	bp->hash.next = hp->hash.next;
	bp->hash.prev = hp;
	hp->hash.next->hash.prev = bp;
	hp->hash.next = bp;
}

static void exfat_remove_dcache_hash(struct exfat_meta_cache *bp)
{
	exfat_remove_from_hash(bp);
}

static struct exfat_meta_cache *exfat_find_fcache(struct super_block *sb,
		unsigned long long sec)
{
	int off;
	struct exfat_meta_cache *bp, *hp;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	off = (sec + (sec >> sbi->sect_per_clus_bits)) &
		(FAT_CACHE_HASH_SIZE - 1);
	hp = &(sbi->fcache.hash_list[off]);
	for (bp = hp->hash.next; bp != hp; bp = bp->hash.next) {
		if (bp->sec == sec) {
			touch_buffer(bp->bh);
			return bp;
		}
	}
	return NULL;
}

static struct exfat_meta_cache *exfat_get_fcache(struct super_block *sb)
{
	struct exfat_meta_cache *bp;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	bp = sbi->fcache.lru_list.prev;
	exfat_move_to_mru(bp, &sbi->fcache.lru_list);
	return bp;
}

static void exfat_insert_fcache_hash(struct super_block *sb, struct exfat_meta_cache *bp)
{
	int off;
	struct exfat_meta_cache *hp;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	off = (bp->sec + (bp->sec >> sbi->sect_per_clus_bits)) &
			(FAT_CACHE_HASH_SIZE-1);

	hp = &(sbi->fcache.hash_list[off]);
	bp->hash.next = hp->hash.next;
	bp->hash.prev = hp;
	hp->hash.next->hash.prev = bp;
	hp->hash.next = bp;
}

static void exfat_remove_fcache_hash(struct exfat_meta_cache *bp)
{
	exfat_remove_from_hash(bp);
}

static void exfat_readahead_blks(struct super_block *sb, unsigned long long secno,
		unsigned long long num_secs)
{
	unsigned long long i;

	for (i = 0; i < num_secs; i++)
		sb_breadahead(sb, (sector_t)(secno + i));
}

static int exfat_discard_fcache(struct super_block *sb, struct exfat_meta_cache *bp)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	exfat_remove_fcache_hash(bp);
	bp->sec = ~0;
	bp->flag = 0;

	if (bp->bh) {
		__brelse(bp->bh);
		bp->bh = NULL;
	}
	exfat_move_to_lru(bp, &sbi->fcache.lru_list);
	return 0;
}

unsigned char *exfat_fcache_getblk(struct super_block *sb, unsigned long long sec)
{
	struct exfat_meta_cache *bp;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int page_ra_count = FCACHE_MAX_RA_SIZE >> sb->s_blocksize_bits;

	bp = exfat_find_fcache(sb, sec);
	if (bp) {
		exfat_move_to_mru(bp, &sbi->fcache.lru_list);
		return bp->bh->b_data;
	}

	bp = exfat_get_fcache(sb);
	if (exfat_check_hash_valid(bp))
		exfat_remove_fcache_hash(bp);

	bp->sec = sec;
	bp->flag = 0;
	exfat_insert_fcache_hash(sb, bp);

	/* Naive FAT read-ahead (increase I/O unit to page_ra_count) */
	if ((sec & (page_ra_count - 1)) == 0)
		exfat_readahead_blks(sb, sec, (unsigned long long)page_ra_count);

	/*
	 * When read_sect is failed, fcache should be moved to
	 * EMPTY hash_list and the first of lru_list.
	 */
	bp->bh = sb_bread(sb, sec);
	if (!bp->bh) {
		exfat_discard_fcache(sb, bp);
		return NULL;
	}

	return bp->bh->b_data;
}

int exfat_update_fcache(struct super_block *sb, unsigned long long sec)
{
	struct exfat_meta_cache *bp;
	int ret = 0;

	bp = exfat_find_fcache(sb, sec);
	if (!bp) {
		exfat_fs_error(sb, "Can`t find fcache (sec 0x%016llx)", sec);
		ret = -EIO;
		goto out;
	}

	set_buffer_uptodate(bp->bh);
	mark_buffer_dirty(bp->bh);

	ret = exfat_mirror_bhs(sb, sec, bp->bh);
out:
	return ret;
}

int exfat_meta_cache_init(struct super_block *sb)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	int i;

	/* LRU list */
	sbi->fcache.lru_list.next = &sbi->fcache.lru_list;
	sbi->fcache.lru_list.prev = sbi->fcache.lru_list.next;

	for (i = 0; i < FAT_CACHE_SIZE; i++) {
		sbi->fcache.pool[i].sec = ~0;
		sbi->fcache.pool[i].flag = 0;
		sbi->fcache.pool[i].bh = NULL;
		sbi->fcache.pool[i].prev = NULL;
		sbi->fcache.pool[i].next = NULL;
		exfat_push_to_mru(&(sbi->fcache.pool[i]), &sbi->fcache.lru_list);
	}

	sbi->dcache.lru_list.next = &sbi->dcache.lru_list;
	sbi->dcache.lru_list.prev = sbi->dcache.lru_list.next;

	// Initially, all the BUF_CACHEs are in the LRU list
	for (i = 0; i < BUF_CACHE_SIZE; i++) {
		sbi->dcache.pool[i].sec = ~0;
		sbi->dcache.pool[i].flag = 0;
		sbi->dcache.pool[i].bh = NULL;
		sbi->dcache.pool[i].prev = NULL;
		sbi->dcache.pool[i].next = NULL;
		exfat_push_to_mru(&(sbi->dcache.pool[i]), &sbi->dcache.lru_list);
	}

	/* HASH list */
	for (i = 0; i < FAT_CACHE_HASH_SIZE; i++) {
		sbi->fcache.hash_list[i].sec = ~0;
		sbi->fcache.hash_list[i].hash.next =
			&(sbi->fcache.hash_list[i]);
		sbi->fcache.hash_list[i].hash.prev =
			sbi->fcache.hash_list[i].hash.next;
	}

	for (i = 0; i < FAT_CACHE_SIZE; i++)
		exfat_insert_fcache_hash(sb, &(sbi->fcache.pool[i]));

	for (i = 0; i < BUF_CACHE_HASH_SIZE; i++) {
		sbi->dcache.hash_list[i].sec = ~0;
		sbi->dcache.hash_list[i].hash.next =
			&(sbi->dcache.hash_list[i]);

		sbi->dcache.hash_list[i].hash.prev =
			sbi->dcache.hash_list[i].hash.next;
	}

	for (i = 0; i < BUF_CACHE_SIZE; i++)
		exfat_insert_dcache_hash(sb, &(sbi->dcache.pool[i]));

	return 0;
}

int exfat_dcache_readahead(struct super_block *sb, unsigned long long sec)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bh;
	unsigned int max_ra_count = DCACHE_MAX_RA_SIZE >> sb->s_blocksize_bits;
	unsigned int page_ra_count = PAGE_SIZE >> sb->s_blocksize_bits;
	unsigned int adj_ra_count = max(sbi->sect_per_clus, page_ra_count);
	unsigned int ra_count = min(adj_ra_count, max_ra_count);

	/* Read-ahead is not required */
	if (sbi->sect_per_clus == 1)
		return 0;

	if (sec < sbi->data_start_sector) {
		exfat_msg(sb, KERN_ERR,
			"requested sector is invalid(sect:%llu, root:%llu)",
			sec, sbi->data_start_sector);
		return -EIO;
	}

	/* Not sector aligned with ra_count, resize ra_count to page size */
	if ((sec - sbi->data_start_sector) & (ra_count - 1))
		ra_count = page_ra_count;

	bh = sb_find_get_block(sb, sec);
	if (!bh || !buffer_uptodate(bh))
		exfat_readahead_blks(sb, sec, (unsigned long long)ra_count);
	brelse(bh);

	return 0;
}

static int exfat_discard_dcache(struct super_block *sb, struct exfat_meta_cache *bp)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	exfat_remove_dcache_hash(bp);
	bp->sec = ~0;
	bp->flag = 0;

	if (bp->bh) {
		__brelse(bp->bh);
		bp->bh = NULL;
	}

	exfat_move_to_lru(bp, &sbi->dcache.lru_list);
	return 0;
}

unsigned char *exfat_dcache_getblk(struct super_block *sb, unsigned long long sec)
{
	struct exfat_meta_cache *bp;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	bp = exfat_find_dcache(sb, sec);
	if (bp) {
		exfat_move_to_mru(bp, &sbi->dcache.lru_list);
		return bp->bh->b_data;
	}

	bp = exfat_get_dcache(sb);

	if (exfat_check_hash_valid(bp))
		exfat_remove_dcache_hash(bp);

	bp->sec = sec;
	bp->flag = 0;
	exfat_insert_dcache_hash(sb, bp);

	bp->bh = sb_bread(sb, sec);
	if (!bp->bh) {
		exfat_discard_dcache(sb, bp);
		return NULL;
	}

	return bp->bh->b_data;
}

int exfat_update_dcache(struct super_block *sb, unsigned long long sec)
{
	struct exfat_meta_cache *bp;

	set_sb_dirty(sb);

	bp = exfat_find_dcache(sb, sec);
	if (unlikely(!bp)) {
		exfat_fs_error(sb, "Can`t find dcache (sec 0x%016llx)", sec);
		return -EIO;
	}

	set_buffer_uptodate(bp->bh);
	mark_buffer_dirty(bp->bh);

	return 0;
}

int exfat_lock_dcache(struct super_block *sb, unsigned long long sec)
{
	struct exfat_meta_cache *bp;

	bp = exfat_find_dcache(sb, sec);
	if (likely(bp)) {
		bp->flag |= LOCKBIT;
		return 0;
	}

	exfat_msg(sb, KERN_ERR, "failed to lock buffer(sec: %llu, bp: 0x%p)",
		sec, bp);
	return -EIO;
}

int exfat_unlock_dcache(struct super_block *sb, unsigned long long sec)
{
	struct exfat_meta_cache *bp;

	bp = exfat_find_dcache(sb, sec);
	if (likely(bp))  {
		bp->flag &= ~(LOCKBIT);
		return 0;
	}

	exfat_msg(sb, KERN_ERR, "failed to unlock buffer (sec: %llu, bp: 0x%p)",
		sec, bp);
	return -EIO;
}

int exfat_release_dcache(struct super_block *sb, unsigned long long sec)
{
	struct exfat_meta_cache *bp;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	bp = exfat_find_dcache(sb, sec);
	if (unlikely(!bp))
		return -ENOENT;

	bp->sec = ~0;
	bp->flag = 0;

	if (bp->bh) {
		__brelse(bp->bh);
		bp->bh = NULL;
	}

	exfat_move_to_lru(bp, &sbi->dcache.lru_list);
	return 0;
}

void exfat_release_caches(struct exfat_meta_cache *lru_list)
{
	struct exfat_meta_cache *bp;

	bp = lru_list->next;
	while (bp != lru_list) {
		bp->sec = ~0;
		bp->flag = 0;

		if (bp->bh) {
			__brelse(bp->bh);
			bp->bh = NULL;
		}
		bp = bp->next;
	}
}
