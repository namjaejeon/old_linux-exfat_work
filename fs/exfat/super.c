// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/mount.h>
#include <linux/cred.h>
#include <linux/statfs.h>
#include <linux/seq_file.h>
#include <linux/parser.h>
#include <linux/blkdev.h>
#include <linux/fs_struct.h>
#include <linux/iversion.h>
#include <linux/nls.h>
#include <linux/buffer_head.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

static int exfat_default_codepage = CONFIG_EXFAT_DEFAULT_CODEPAGE;
static char exfat_default_iocharset[] = CONFIG_EXFAT_DEFAULT_IOCHARSET;
static const char exfat_iocharset_with_utf8[] = "iso8859-1";
static struct kmem_cache *exfat_inode_cachep;

static void exfat_put_super(struct super_block *sb)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	mutex_lock(&sbi->s_lock);
	if (READ_ONCE(sbi->s_dirt)) {
		WRITE_ONCE(sbi->s_dirt, true);
		sync_blockdev(sb->s_bdev);
	}
	exfat_set_vol_flags(sb, VOL_CLEAN);
	exfat_free_upcase_table(sb);
	exfat_free_alloc_bmp(sb);
	mutex_unlock(&sbi->s_lock);

	if (sbi->nls_disk) {
		unload_nls(sbi->nls_disk);
		sbi->nls_disk = NULL;
		sbi->options.codepage = exfat_default_codepage;
	}
	if (sbi->nls_io) {
		unload_nls(sbi->nls_io);
		sbi->nls_io = NULL;
	}
	if (sbi->options.iocharset != exfat_default_iocharset) {
		kfree(sbi->options.iocharset);
		sbi->options.iocharset = exfat_default_iocharset;
	}

	sb->s_fs_info = NULL;
	kfree(sbi);
}

static int exfat_sync_fs(struct super_block *sb, int wait)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	int err = 0;

	/* If there are some dirty buffers in the bdev inode */
	mutex_lock(&sbi->s_lock);
	if (READ_ONCE(sbi->s_dirt)) {
		WRITE_ONCE(sbi->s_dirt, true);
		sync_blockdev(sb->s_bdev);
		if (exfat_set_vol_flags(sb, VOL_CLEAN))
			err = -EIO;
	}
	mutex_unlock(&sbi->s_lock);

	return err;
}

static int exfat_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned long long id = huge_encode_dev(sb->s_bdev->bd_dev);

	if (sbi->used_clusters == ~0u) {
		mutex_lock(&sbi->s_lock);
		if (exfat_count_used_clusters(sb, &sbi->used_clusters)) {
			mutex_unlock(&sbi->s_lock);
			return -EIO;
		}
		mutex_unlock(&sbi->s_lock);
	}

	buf->f_type = sb->s_magic;
	buf->f_bsize = sbi->cluster_size;
	buf->f_blocks = sbi->num_clusters - 2; /* clu 0 & 1 */
	buf->f_bfree = buf->f_blocks -
		(sbi->used_clusters + sbi->reserved_clusters);
	buf->f_bavail = buf->f_bfree;
	buf->f_fsid.val[0] = (unsigned int)id;
	buf->f_fsid.val[1] = (unsigned int)(id >> 32);
	buf->f_namelen = 260;

	return 0;
}

static int __exfat_set_vol_flags(struct super_block *sb,
		unsigned short new_flag, int always_sync)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct pbr64 *bpb;
	int sync = 0;

	/* flags are not changed */
	if (sbi->vol_flag == new_flag)
		return 0;

	sbi->vol_flag = new_flag;

	/* skip updating volume dirty flag,
	 * if this volume has been mounted with read-only
	 */
	if (sb_rdonly(sb))
		return 0;

	if (!sbi->pbr_bh) {
		sbi->pbr_bh = sb_bread(sb, 0);
		if (!sbi->pbr_bh) {
			exfat_msg(sb, KERN_ERR, "failed to read boot sector");
			return -ENOMEM;
		}
	}

	bpb = (struct pbr64 *)sbi->pbr_bh->b_data;
	bpb->bsx.vol_flags = cpu_to_le16(new_flag);

	if (always_sync)
		sync = 1;
	else if ((new_flag == VOL_DIRTY) && (!buffer_dirty(sbi->pbr_bh)))
		sync = 1;
	else
		sync = 0;

	set_buffer_uptodate(sbi->pbr_bh);
	mark_buffer_dirty(sbi->pbr_bh);

	if (sync)
		sync_dirty_buffer(sbi->pbr_bh);
	return 0;
}

int exfat_set_vol_flags(struct super_block *sb, unsigned short new_flag)
{
	return __exfat_set_vol_flags(sb, new_flag, 0);
}

static int exfat_remount(struct super_block *sb, int *flags, char *data)
{
	unsigned long prev_sb_flags;
	char *orig_data = kstrdup(data, GFP_KERNEL);

	*flags |= SB_NODIRATIME;

	prev_sb_flags = sb->s_flags;
	sync_filesystem(sb);
	__exfat_set_vol_flags(sb, VOL_CLEAN, 1);
	kfree(orig_data);
	return 0;
}

static int __exfat_show_options(struct seq_file *m, struct super_block *sb)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_mount_options *opts = &sbi->options;

	/* Show partition info */
	if (!uid_eq(opts->fs_uid, GLOBAL_ROOT_UID))
		seq_printf(m, ",uid=%u",
				from_kuid_munged(&init_user_ns, opts->fs_uid));
	if (!gid_eq(opts->fs_gid, GLOBAL_ROOT_GID))
		seq_printf(m, ",gid=%u",
				from_kgid_munged(&init_user_ns, opts->fs_gid));
	seq_printf(m, ",fmask=%04o", opts->fs_fmask);
	seq_printf(m, ",dmask=%04o", opts->fs_dmask);
	if (opts->allow_utime)
		seq_printf(m, ",allow_utime=%04o", opts->allow_utime);
	if (sbi->nls_disk)
		seq_printf(m, ",codepage=%s", sbi->nls_disk->charset);
	if (sbi->nls_io)
		seq_printf(m, ",iocharset=%s", sbi->nls_io->charset);
	if (opts->utf8)
		seq_puts(m, ",utf8");
	seq_printf(m, ",namecase=%u", opts->casesensitive);
	if (opts->tz_utc)
		seq_puts(m, ",tz=UTC");
	seq_printf(m, ",bps=%ld", sb->s_blocksize);
	if (opts->errors == EXFAT_ERRORS_CONT)
		seq_puts(m, ",errors=continue");
	else if (opts->errors == EXFAT_ERRORS_PANIC)
		seq_puts(m, ",errors=panic");
	else
		seq_puts(m, ",errors=remount-ro");
	if (opts->discard)
		seq_puts(m, ",discard");

	return 0;
}

static int exfat_show_options(struct seq_file *m, struct dentry *root)
{
	return __exfat_show_options(m, root->d_sb);
}

static struct inode *exfat_alloc_inode(struct super_block *sb)
{
	struct exfat_inode_info *ei;

	ei = kmem_cache_alloc(exfat_inode_cachep, GFP_NOFS);
	if (!ei)
		return NULL;

	init_rwsem(&ei->truncate_lock);
	return &ei->vfs_inode;
}

static void exfat_destroy_inode(struct inode *inode)
{
	kmem_cache_free(exfat_inode_cachep, EXFAT_I(inode));
}

static const struct super_operations exfat_sops = {
	.alloc_inode   = exfat_alloc_inode,
	.destroy_inode = exfat_destroy_inode,
	.write_inode   = exfat_write_inode,
	.evict_inode  = exfat_evict_inode,
	.put_super     = exfat_put_super,
	.sync_fs       = exfat_sync_fs,
	.statfs        = exfat_statfs,
	.remount_fs    = exfat_remount,
	.show_options  = exfat_show_options,
};

enum {
	Opt_uid,
	Opt_gid,
	Opt_umask,
	Opt_dmask,
	Opt_fmask,
	Opt_allow_utime,
	Opt_codepage,
	Opt_charset,
	Opt_utf8,
	Opt_namecase,
	Opt_tz_utc,
	Opt_debug,
	Opt_err_cont,
	Opt_err_panic,
	Opt_err_ro,
	Opt_err,
	Opt_discard,
	Opt_fs,
};

static const match_table_t exfat_tokens = {
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_umask, "umask=%o"},
	{Opt_dmask, "dmask=%o"},
	{Opt_fmask, "fmask=%o"},
	{Opt_allow_utime, "allow_utime=%o"},
	{Opt_codepage, "codepage=%u"},
	{Opt_charset, "iocharset=%s"},
	{Opt_utf8, "utf8"},
	{Opt_namecase, "namecase=%u"},
	{Opt_tz_utc, "tz=UTC"},
	{Opt_err_cont, "errors=continue"},
	{Opt_err_panic, "errors=panic"},
	{Opt_err_ro, "errors=remount-ro"},
	{Opt_discard, "discard"},
	{Opt_err, NULL}
};

static int parse_options(struct super_block *sb, char *options, int silent,
		struct exfat_mount_options *opts)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;
	char *tmpstr;

	opts->fs_uid = current_uid();
	opts->fs_gid = current_gid();
	opts->fs_fmask = opts->fs_dmask = current->fs->umask;
	opts->allow_utime = -1;
	opts->codepage = exfat_default_codepage;
	opts->iocharset = exfat_default_iocharset;
	opts->casesensitive = 0;
	opts->utf8 = 0;
	opts->tz_utc = 0;
	opts->errors = EXFAT_ERRORS_RO;
	opts->discard = 0;

	if (!options)
		goto out;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;
		token = match_token(p, exfat_tokens, args);
		switch (token) {
		case Opt_uid:
			if (match_int(&args[0], &option))
				return 0;
			opts->fs_uid = make_kuid(current_user_ns(), option);
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				return 0;
			opts->fs_gid = make_kgid(current_user_ns(), option);
				break;
		case Opt_umask:
		case Opt_dmask:
		case Opt_fmask:
			if (match_octal(&args[0], &option))
				return 0;
			if (token != Opt_dmask)
				opts->fs_fmask = option;
			if (token != Opt_fmask)
				opts->fs_dmask = option;
			break;
		case Opt_allow_utime:
			if (match_octal(&args[0], &option))
				return 0;
			opts->allow_utime = option & (0022);
			break;
		case Opt_codepage:
			if (match_int(&args[0], &option))
				return 0;
			opts->codepage = option;
			break;
		case Opt_charset:
			if (opts->iocharset != exfat_default_iocharset)
				kfree(opts->iocharset);
			tmpstr = match_strdup(&args[0]);
			if (!tmpstr)
				return -ENOMEM;
			opts->iocharset = tmpstr;
			break;
		case Opt_namecase:
			if (match_int(&args[0], &option))
				return 0;
			opts->casesensitive = (option > 0) ? 1:0;
			break;
		case Opt_utf8:
			opts->utf8 = 1;
			break;
		case Opt_tz_utc:
			opts->tz_utc = 1;
			break;
		case Opt_err_cont:
			opts->errors = EXFAT_ERRORS_CONT;
			break;
		case Opt_err_panic:
			opts->errors = EXFAT_ERRORS_PANIC;
			break;
		case Opt_err_ro:
			opts->errors = EXFAT_ERRORS_RO;
			break;
		case Opt_discard:
			opts->discard = 1;
			break;
		default:
			if (!silent) {
				exfat_msg(sb, KERN_ERR,
					"unrecognized mount option \"%s\" or missing value",
					p);
			}
			return -EINVAL;
		}
	}

out:
	if (opts->allow_utime == -1)
		opts->allow_utime = ~opts->fs_dmask & (0022);

	if (opts->utf8 && strcmp(opts->iocharset, exfat_iocharset_with_utf8)) {
		exfat_msg(sb, KERN_WARNING,
			"utf8 enabled, \"iocharset=%s\" is recommended",
			exfat_iocharset_with_utf8);
	}

	if (opts->discard) {
		struct request_queue *q = bdev_get_queue(sb->s_bdev);

		if (!blk_queue_discard(q))
			exfat_msg(sb, KERN_WARNING,
				"mounting with \"discard\" option, but the device does not support discard");
		opts->discard = 0;
	}

	return 0;
}

static void exfat_hash_init(struct super_block *sb)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	int i;

	spin_lock_init(&sbi->inode_hash_lock);
	for (i = 0; i < EXFAT_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&sbi->inode_hashtable[i]);
}

static int exfat_read_root(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct exfat_chain cdir;
	int num_subdirs, num_clu;

	ei->dir.dir = sbi->root_dir;
	ei->dir.flags = 0x01;
	ei->entry = -1;
	ei->start_clu = sbi->root_dir;
	ei->flags = 0x01;
	ei->type = TYPE_DIR;
	ei->version = 0;
	ei->rwoffset = 0;
	ei->hint_bmap.off = EOF_CLUSTER;
	ei->hint_stat.eidx = 0;
	ei->hint_stat.clu = sbi->root_dir;
	ei->hint_femp.eidx = EXFAT_HINT_NONE;

	cdir.dir = sbi->root_dir;
	cdir.flags = 0x01;
	cdir.size = 0; /* UNUSED */
	if (exfat_count_num_clusters(sb, &cdir, &num_clu))
		return -EIO;
	i_size_write(inode, num_clu << sbi->cluster_size_bits);

	num_subdirs = exfat_count_dir_entries(sb, &cdir);
	if (num_subdirs < 0)
		return -EIO;
	set_nlink(inode, num_subdirs + EXFAT_MIN_SUBDIR);

	inode->i_uid = sbi->options.fs_uid;
	inode->i_gid = sbi->options.fs_gid;
	inode_inc_iversion(inode);
	inode->i_generation = 0;
	inode->i_mode = exfat_make_mode(sbi, ATTR_SUBDIR, 0777);
	inode->i_op = &exfat_dir_inode_operations;
	inode->i_fop = &exfat_dir_operations;

	inode->i_blocks = ((i_size_read(inode) + (sbi->cluster_size - 1))
			& ~(sbi->cluster_size - 1)) >> inode->i_blkbits;
	EXFAT_I(inode)->i_pos = ((loff_t)sbi->root_dir << 32) | 0xffffffff;
	EXFAT_I(inode)->i_size_aligned = i_size_read(inode);
	EXFAT_I(inode)->i_size_ondisk = i_size_read(inode);

	exfat_save_attr(inode, ATTR_SUBDIR);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	exfat_cache_init_inode(inode);
	return 0;
}

static void exfat_setup_dops(struct super_block *sb)
{
	if (EXFAT_SB(sb)->options.casesensitive == 0)
		sb->s_d_op = &exfat_ci_dentry_ops;
	else
		sb->s_d_op = &exfat_dentry_ops;
}

static bool is_exfat(struct pbr *pbr)
{
	int i = 53;

	do {
		if (pbr->bpb.f64.res_zero[i - 1])
			break;
	} while (--i);
	return i ? false : true;
}

static struct pbr *exfat_read_pbr_with_logical_sector(struct super_block *sb,
		struct buffer_head **prev_bh)
{
	struct pbr *p_pbr = (struct pbr *) (*prev_bh)->b_data;
	unsigned short logical_sect = 0;

	logical_sect = 1 << p_pbr->bsx.f64.sect_size_bits;

	/* is x a power of 2?
	 * (x) != 0 && (((x) & ((x) - 1)) == 0)
	 */
	if (!is_power_of_2(logical_sect)
		|| (logical_sect < 512)
		|| (logical_sect > 4096)) {
		exfat_msg(sb, KERN_ERR, "bogus logical sector size %u",
				logical_sect);
		return NULL;
	}

	if (logical_sect < sb->s_blocksize) {
		exfat_msg(sb, KERN_ERR,
			"logical sector size too small for device (logical sector size = %u)",
			logical_sect);
		return NULL;
	}

	if (logical_sect > sb->s_blocksize) {
		struct buffer_head *bh = NULL;

		__brelse(*prev_bh);
		*prev_bh = NULL;

		if (!sb_set_blocksize(sb, logical_sect)) {
			exfat_msg(sb, KERN_ERR,
				"unable to set blocksize %u", logical_sect);
			return NULL;
		}
		bh = sb_bread(sb, 0);
		if (!bh) {
			exfat_msg(sb, KERN_ERR,
				"unable to read boot sector (logical sector size = %lu)",
				sb->s_blocksize);
			return NULL;
		}

		*prev_bh = bh;
		p_pbr = (struct pbr *) bh->b_data;
	}

	return p_pbr;
}

/* mount the file system volume */
static int __exfat_fill_super(struct super_block *sb)
{
	int ret;
	struct pbr *p_pbr;
	struct pbr64 *p_bpb;
	struct buffer_head *bh;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	/* set block size to read super block */
	sb_min_blocksize(sb, 512);

	/* read boot sector */
	bh = sb_bread(sb, 0);
	if (!bh) {
		exfat_msg(sb, KERN_ERR, "unable to read boot sector");
		ret = -EIO;
		goto out;
	}

	/* PRB is read */
	p_pbr = (struct pbr *)bh->b_data;

	/* check the validity of PBR */
	if (le16_to_cpu((p_pbr->signature)) != PBR_SIGNATURE) {
		exfat_msg(sb, KERN_ERR, "invalid boot record signature");
		ret = -EINVAL;
		goto free_bh;
	}

	/* check logical sector size */
	p_pbr = exfat_read_pbr_with_logical_sector(sb, &bh);
	if (!p_pbr) {
		ret = -EIO;
		goto free_bh;
	}

	if (!is_exfat(p_pbr)) {
		ret = -EINVAL;
		goto free_bh;
	}

	/* set maximum file size for exFAT */
	sb->s_maxbytes = 0x7fffffffffffffffLL;

	p_bpb = (struct pbr64 *)p_pbr;
	if (!p_bpb->bsx.num_fats) {
		exfat_msg(sb, KERN_ERR, "bogus number of FAT structure");
		ret = -EINVAL;
		goto free_bh;
	}

	sbi->sect_per_clus = 1 << p_bpb->bsx.sect_per_clus_bits;
	sbi->sect_per_clus_bits = p_bpb->bsx.sect_per_clus_bits;
	sbi->cluster_size_bits = sbi->sect_per_clus_bits + sb->s_blocksize_bits;
	sbi->cluster_size = 1 << sbi->cluster_size_bits;
	sbi->num_FAT_sectors = le32_to_cpu(p_bpb->bsx.fat_length);
	sbi->FAT1_start_sector = le32_to_cpu(p_bpb->bsx.fat_offset);

	if (p_bpb->bsx.num_fats == 1)
		sbi->FAT2_start_sector = sbi->FAT1_start_sector;
	else
		sbi->FAT2_start_sector =
			sbi->FAT1_start_sector + sbi->num_FAT_sectors;

	sbi->root_start_sector = le32_to_cpu(p_bpb->bsx.clu_offset);
	sbi->data_start_sector = sbi->root_start_sector;
	sbi->num_sectors = le64_to_cpu(p_bpb->bsx.vol_length);
	/* because the cluster index starts with 2 */
	sbi->num_clusters = le32_to_cpu(p_bpb->bsx.clu_count) + 2;

	sbi->vol_id = le32_to_cpu(p_bpb->bsx.vol_serial);
	sbi->root_dir = le32_to_cpu(p_bpb->bsx.root_cluster);
	sbi->dentries_in_root = 0;
	sbi->dentries_per_clu = 1 <<
		(sbi->cluster_size_bits - DENTRY_SIZE_BITS);

	sbi->vol_flag = le16_to_cpu(p_bpb->bsx.vol_flags);
	sbi->clu_srch_ptr = BASE_CLUSTER;
	sbi->used_clusters = ~0u;

	if (le16_to_cpu(p_bpb->bsx.vol_flags) & VOL_DIRTY) {
		sbi->vol_flag |= VOL_DIRTY;
		exfat_msg(sb, KERN_WARNING,
			"Volume was not properly unmounted. Some data may be corrupt. Please run fsck.");
	}

	ret = exfat_create_upcase_table(sb);
	if (ret) {
		exfat_msg(sb, KERN_ERR, "failed to load upcase table");
		goto out;
	}

	/* allocate-bitmap is only for exFAT */
	ret = exfat_load_alloc_bmp(sb);
	if (ret) {
		exfat_msg(sb, KERN_ERR, "failed to load alloc-bitmap");
		goto free_upcase;
	}

	ret = exfat_count_used_clusters(sb, &sbi->used_clusters);
	if (ret) {
		exfat_msg(sb, KERN_ERR, "failed to scan clusters");
		goto free_alloc_bmp;
	}

	return 0;

free_alloc_bmp:
	exfat_free_alloc_bmp(sb);
free_upcase:
	exfat_free_upcase_table(sb);
free_bh:
	brelse(bh);
out:
	return ret;
}

static int exfat_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *root_inode = NULL;
	struct exfat_sb_info *sbi;
	int err;
	char buf[50];

	/*
	 * GFP_KERNEL is ok here, because while we do hold the
	 * supeblock lock, memory pressure can't call back into
	 * the filesystem, since we're only just about to mount
	 * it and have no inodes etc active!
	 */
	sbi = kzalloc(sizeof(struct exfat_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	mutex_init(&sbi->s_lock);
	sb->s_fs_info = sbi;
	sb->s_flags |= SB_NODIRATIME;
	sb->s_magic = EXFAT_SUPER_MAGIC;
	sb->s_op = &exfat_sops;
	ratelimit_state_init(&sbi->ratelimit, DEFAULT_RATELIMIT_INTERVAL,
			DEFAULT_RATELIMIT_BURST);
	err = parse_options(sb, data, silent, &sbi->options);
	if (err) {
		exfat_msg(sb, KERN_ERR, "failed to parse options");
		goto failed_mount;
	}

	exfat_setup_dops(sb);

	err = __exfat_fill_super(sb);
	if (err) {
		exfat_msg(sb, KERN_ERR, "failed to recognize exfat type");
		goto failed_mount;
	}

	/* set up enough so that it can read an inode */
	exfat_hash_init(sb);

	/*
	 * The low byte of FAT's first entry must have same value with
	 * media-field.  But in real world, too many devices is
	 * writing wrong value.  So, removed that validity check.
	 *
	 * if (FAT_FIRST_ENT(sb, media) != first)
	 */

	err = -EINVAL;
	sprintf(buf, "cp%d", sbi->options.codepage);
	sbi->nls_disk = load_nls(buf);
	if (!sbi->nls_disk) {
		exfat_msg(sb, KERN_ERR, "codepage %s not found", buf);
		goto failed_mount2;
	}

	sbi->nls_io = load_nls(sbi->options.iocharset);
	if (!sbi->nls_io) {
		exfat_msg(sb, KERN_ERR, "IO charset %s not found",
				sbi->options.iocharset);
		goto failed_mount2;
	}

	err = -ENOMEM;
	root_inode = new_inode(sb);
	if (!root_inode) {
		exfat_msg(sb, KERN_ERR, "failed to allocate root inode.");
		goto failed_mount2;
	}

	root_inode->i_ino = EXFAT_ROOT_INO;
	inode_set_iversion(root_inode, 1);
	err = exfat_read_root(root_inode);
	if (err) {
		exfat_msg(sb, KERN_ERR, "failed to initialize root inode.");
		goto failed_mount2;
	}

	exfat_hash_inode(root_inode, EXFAT_I(root_inode)->i_pos);
	insert_inode_hash(root_inode);

	err = -ENOMEM;
	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root) {
		exfat_msg(sb, KERN_ERR, "failed to get the root dentry");
		goto failed_mount2;
	}

	return 0;

failed_mount2:
	exfat_free_upcase_table(sb);
	exfat_free_alloc_bmp(sb);

failed_mount:
	if (root_inode)
		iput(root_inode);
	sb->s_root = NULL;

	if (sbi->nls_io)
		unload_nls(sbi->nls_io);
	if (sbi->nls_disk)
		unload_nls(sbi->nls_disk);
	if (sbi->options.iocharset != exfat_default_iocharset)
		kfree(sbi->options.iocharset);
	sb->s_fs_info = NULL;
	kfree(sbi);
	return err;
}

static struct dentry *exfat_fs_mount(struct file_system_type *fs_type,
		int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, exfat_fill_super);
}

static void exfat_inode_init_once(void *foo)
{
	struct exfat_inode_info *ei = (struct exfat_inode_info *)foo;

	INIT_HLIST_NODE(&ei->i_hash_fat);
	inode_init_once(&ei->vfs_inode);
}

static struct file_system_type exfat_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "exfat",
	.mount		= exfat_fs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};

static int __init init_exfat_fs(void)
{
	int err;

	err = exfat_cache_init();
	if (err)
		goto error;

	err = -ENOMEM;
	exfat_inode_cachep = kmem_cache_create("exfat_inode_cache",
			sizeof(struct exfat_inode_info),
			0, SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD,
			exfat_inode_init_once);
	if (!exfat_inode_cachep)
		goto error;

	err = register_filesystem(&exfat_fs_type);
	if (err)
		goto error;

	return 0;
error:
	kmem_cache_destroy(exfat_inode_cachep);
	exfat_cache_shutdown();

	return err;
}

static void __exit exit_exfat_fs(void)
{
	kmem_cache_destroy(exfat_inode_cachep);
	unregister_filesystem(&exfat_fs_type);
	exfat_cache_shutdown();
}

module_init(init_exfat_fs);
module_exit(exit_exfat_fs);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("exFAT filesystem support");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
