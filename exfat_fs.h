/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */


#ifndef _EXFAT_H
#define _EXFAT_H

#include <linux/module.h>
#include <linux/init.h>
#include <linux/buffer_head.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/nls.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/ratelimit.h>
#include <linux/version.h>

/* Read-ahead related                                */
/* First config vars. should be pow of 2             */
#define FCACHE_MAX_RA_SIZE      (PAGE_SIZE)
#define DCACHE_MAX_RA_SIZE      (128*1024)

#define FAT_CACHE_SIZE          128
#define FAT_CACHE_HASH_SIZE     64
#define BUF_CACHE_SIZE          256
#define BUF_CACHE_HASH_SIZE     64

#define SECTOR_SIZE_BITS    9   /* VFS sector size is 512 bytes */

/* time modes */
#define TM_CREATE               0
#define TM_MODIFY               1
#define TM_ACCESS               2

/*
 * exfat allocator destination for smart allocation
 */
#define ALLOC_NOWHERE           (0)
#define ALLOC_COLD              (1)
#define ALLOC_HOT               (16)
#define ALLOC_COLD_ALIGNED      (1)
#define ALLOC_COLD_PACKING      (2)
#define ALLOC_COLD_SEQ          (4)

/*
 * exfat error flags
 */
#define EXFAT_ERRORS_CONT	(1)    /* ignore error and continue */
#define EXFAT_ERRORS_PANIC	(2)    /* panic on error */
#define EXFAT_ERRORS_RO		(3)    /* remount r/o on error */

/*
 * exfat allocator flags
 */
#define EXFAT_ALLOC_DELAY	(1)    /* Delayed allocation */
#define EXFAT_ALLOC_SMART	(2)    /* Smart allocation */

/*
 * exfat nls lossy flag
 */
#define NLS_NAME_NO_LOSSY	(0x00) /* no lossy */
#define NLS_NAME_LOSSY		(0x01) /* just detected incorrect filename(s) */
#define NLS_NAME_OVERLEN	(0x02) /* the length is over than its limit */

/*
 * exfat common MACRO
 */
#define CLUSTER_16(x)	((unsigned short)((x) & 0xFFFFU))
#define CLUSTER_32(x)	((unsigned int)((x) & 0xFFFFFFFFU))
#define CLUS_EOF	CLUSTER_32(~0)
#define CLUS_BAD	(0xFFFFFFF7U)
#define CLUS_FREE	(0)
#define CLUS_BASE	(2)
#define IS_CLUS_EOF(x)	((x) == CLUS_EOF)
#define IS_CLUS_BAD(x)	((x) == CLUS_BAD)
#define IS_CLUS_FREE(x)	((x) == CLUS_FREE)
#define IS_LAST_SECT_IN_CLUS(sbi, sec)				\
	((((sec) - (sbi)->data_start_sector + 1)		\
	  & ((1 << (sbi)->sect_per_clus_bits) - 1)) == 0)

#define CLUS_TO_SECT(sbi, x)	\
	((((unsigned long long)(x) - CLUS_BASE) << (sbi)->sect_per_clus_bits) + (sbi)->data_start_sector)

#define SECT_TO_CLUS(sbi, sec)	\
	((unsigned int)((((sec) - (sbi)->data_start_sector) >> (sbi)->sect_per_clus_bits) + CLUS_BASE))

#define EXFAT_HASH_BITS    8
#define EXFAT_HASH_SIZE    (1UL << EXFAT_HASH_BITS)

/* directory file name */
#define DOS_CUR_DIR_NAME        ".          "
#define DOS_PAR_DIR_NAME        "..         "

#define DENTRY_SIZE             32      /* directory entry size */
#define DENTRY_SIZE_BITS    5

#define EXFAT_ROOT_INO          1

/*----------------------------------------------------------------------*/
/*  Type Definitions                                                    */
/*----------------------------------------------------------------------*/
#define ES_2_ENTRIES        2
#define ES_3_ENTRIES        3
#define ES_ALL_ENTRIES  0

#define DIR_DELETED             0xFFFF0321

#define VOL_CLEAN   0x0000
#define VOL_DIRTY   0x0001

/* type values */
#define TYPE_UNUSED             0x0000
#define TYPE_DELETED            0x0001
#define TYPE_INVALID            0x0002
#define TYPE_CRITICAL_PRI       0x0100
#define TYPE_BITMAP             0x0101
#define TYPE_UPCASE             0x0102
#define TYPE_VOLUME             0x0103
#define TYPE_DIR                0x0104
#define TYPE_FILE               0x011F
#define TYPE_SYMLINK            0x015F
#define TYPE_CRITICAL_SEC       0x0200
#define TYPE_STREAM             0x0201
#define TYPE_EXTEND             0x0202
#define TYPE_ACL                0x0203
#define TYPE_BENIGN_PRI         0x0400
#define TYPE_GUID               0x0401
#define TYPE_PADDING            0x0402
#define TYPE_ACLTAB             0x0403
#define TYPE_BENIGN_SEC         0x0800
#define TYPE_ALL                0x0FFF

#define MAX_CHARSET_SIZE        6       // max size of multi-byte character
#define MAX_NAME_LENGTH         255     // max len of file name excluding NULL
#define DOS_NAME_LENGTH         11      // DOS file name length excluding NULL
#define MAX_VFSNAME_BUF_SIZE       ((MAX_NAME_LENGTH + 1) * MAX_CHARSET_SIZE)
#define MAX_DOSNAME_BUF_SIZE       ((DOS_NAME_LENGTH + 2) + 6)

/* file creation modes */
#define FM_REGULAR              0x00
#define FM_SYMLINK              0x40

struct exfat_dos_dentry {
	__u8    name[DOS_NAME_LENGTH];  /* 11 chars */
	__u8    attr;
	__u8    lcase;
	__u8    create_time_ms;
	__le16  create_time;             // aligned
	__le16  create_date;             // aligned
	__le16  access_date;             // aligned
	__le16  start_clu_hi;            // aligned
	__le16  modify_time;             // aligned
	__le16  modify_date;             // aligned
	__le16  start_clu_lo;            // aligned
	__le32  size;                    // aligned
};

struct exfat_timestamp {
	unsigned short      sec;        /* 0 ~ 59               */
	unsigned short      min;        /* 0 ~ 59               */
	unsigned short      hour;       /* 0 ~ 23               */
	unsigned short      day;        /* 1 ~ 31               */
	unsigned short      mon;        /* 1 ~ 12               */
	unsigned short      year;       /* 0 ~ 127 (since 1980) */
};

struct exfat_date_time {
	unsigned short      year;
	unsigned short      month;
	unsigned short      day;
	unsigned short      hour;
	unsigned short      minute;
	unsigned short      second;
	unsigned short      milli_second;
};

struct exfat_dentry_namebuf {
	char *lfn;
	char *sfn;
	int lfnbuf_len; //usally MAX_UNINAME_BUF_SIZE
	int sfnbuf_len; //usally MAX_DOSNAME_BUF_SIZE, used only for vfat, not for exfat
};

struct exfat_dir_entry {
	unsigned int attr;
	unsigned long long size;
	unsigned int num_subdirs;
	struct exfat_date_time create_timestamp;
	struct exfat_date_time modify_timestamp;
	struct exfat_date_time access_timestamp;
	struct exfat_dentry_namebuf namebuf;
};

/* DOS name structure */
struct exfat_dos_name {
	unsigned char       name[DOS_NAME_LENGTH];
	unsigned char       name_case;
};

/* unicode name structure */
struct exfat_uni_name {
	unsigned short      name[MAX_NAME_LENGTH+3]; /* +3 for null and for converting */
	unsigned short      name_hash;
	unsigned char       name_len;
};

/* directory structure */
struct exfat_chain {
	unsigned int      dir;
	unsigned int      size;
	unsigned char       flags;
};

/* first empty entry hint information */
struct exfat_hint_femp {
	int eidx;               // entry index of a directory
	int count;              // count of continuous empty entry
	struct exfat_chain cur;            // the cluster that first empty slot exists in
};

/* hint structure */
struct exfat_hint {
	unsigned int      clu;
	union {
		unsigned int off;     // cluster offset
		int eidx;    // entry index
	};
};

struct exfat_entry_set_cache {
	unsigned long long sector;     // sector number that contains file_entry
	unsigned int offset;     // byte offset in the sector
	int alloc_flag; // flag in stream entry. 01 for cluster chain, 03 for contig. clusters.
	unsigned int num_entries;
	void    *__buf;     // __buf should be the last member
};

struct exfat_cache_lru {
	spinlock_t cache_lru_lock;
	struct list_head cache_lru;
	int nr_caches;
	unsigned int cache_valid_id;     // for avoiding the race between alloc and free
};

/*
 * exfat mount in-memory data
 */
struct exfat_mount_options {
	kuid_t fs_uid;
	kgid_t fs_gid;
	unsigned short fs_fmask;
	unsigned short fs_dmask;
	unsigned short allow_utime; /* permission for setting the [am]time */
	unsigned short codepage;    /* codepage for shortname conversions */
	char *iocharset;            /* charset for filename input/display */
	unsigned char utf8;
	unsigned char casesensitive;
	unsigned char tz_utc;
	unsigned char symlink;      /* support symlink operation */
	unsigned char errors;       /* on error: continue, panic, remount-ro */
	unsigned char discard;      /* flag on if -o dicard specified and device support discard() */
};

/* cache information */
struct exfat_cache_entry {
	struct exfat_cache_entry *next;
	struct exfat_cache_entry *prev;
	struct {
		struct exfat_cache_entry *next;
		struct exfat_cache_entry *prev;
	} hash;
	unsigned long long sec;
	unsigned int flag;
	struct buffer_head   *bh;
};

/*
 * EXFAT file system superblock in-memory data
 */
struct exfat_sb_info {
	unsigned int      vol_type;               // volume FAT type
	unsigned int      vol_id;                 // volume serial number
	unsigned long long      num_sectors;            // num of sectors in volume
	unsigned int      num_clusters;           // num of clusters in volume
	unsigned int      cluster_size;           // cluster size in bytes
	unsigned int      cluster_size_bits;
	unsigned int      sect_per_clus;        // cluster size in sectors
	unsigned int      sect_per_clus_bits;
	unsigned long long      FAT1_start_sector;      // FAT1 start sector
	unsigned long long      FAT2_start_sector;      // FAT2 start sector
	unsigned long long      root_start_sector;      // root dir start sector
	unsigned long long      data_start_sector;      // data area start sector
	unsigned int      num_FAT_sectors;        // num of FAT sectors
	unsigned int      root_dir;               // root dir cluster
	unsigned int      dentries_in_root;       // num of dentries in root dir
	unsigned int      dentries_per_clu;       // num of dentries per cluster
	unsigned int      vol_flag;               // volume dirty flag
	struct buffer_head *pbr_bh;      // buffer_head of PBR sector

	unsigned int      map_clu;                // allocation bitmap start cluster
	unsigned int      map_sectors;            // num of allocation bitmap sectors
	struct buffer_head **vol_amap;      // allocation bitmap

	unsigned short      **vol_utbl;               // upcase table

	unsigned int      clu_srch_ptr;           // cluster search pointer
	unsigned int      used_clusters;          // number of used clusters

	unsigned int      prev_eio;            // block device operation error flag

	int       reserved_clusters;  // # of reserved clusters (DA)
	void        *amap;                  // AU Allocation Map

	/* fat cache */
	struct {
		struct exfat_cache_entry pool[FAT_CACHE_SIZE];
		struct exfat_cache_entry lru_list;
		struct exfat_cache_entry hash_list[FAT_CACHE_HASH_SIZE];
	} fcache;

	/* meta cache */
	struct {
		struct exfat_cache_entry pool[BUF_CACHE_SIZE];
		struct exfat_cache_entry lru_list;
		struct exfat_cache_entry keep_list;        // CACHEs in this list will not be kicked by normal lru operations
		struct exfat_cache_entry hash_list[BUF_CACHE_HASH_SIZE];
	} dcache;

	int s_dirt;
	struct mutex s_lock;    /* superblock lock */
	struct super_block *host_sb;		/* sb pointer */
	struct exfat_mount_options options;
	struct nls_table *nls_disk; /* Codepage used on disk */
	struct nls_table *nls_io;   /* Charset used for input and display */
	struct ratelimit_state ratelimit;

	spinlock_t inode_hash_lock;
	struct hlist_head inode_hashtable[EXFAT_HASH_SIZE];
};

struct exfat_file_id {
	struct exfat_chain dir;
	int entry;
	unsigned int type;
	unsigned int attr;
	unsigned int start_clu;
	unsigned long long size;
	unsigned char  flags;
	unsigned char  reserved[3];        // padding
	unsigned int version;            // the copy of low 32bit of i_version to check the validation of hint_stat
	s64 rwoffset;           // file offset or dentry index for readdir
	struct exfat_cache_lru exfat_lru;        // exfat cache for a file
	struct exfat_hint hint_bmap;      // hint for cluster last accessed
	struct exfat_hint  hint_stat;      // hint for entry index we try to lookup next time
	struct exfat_hint_femp hint_femp; // hint for first empty entry
};

/*
 * EXFAT file system inode in-memory data
 */
struct exfat_inode_info {
	struct exfat_file_id fid;

	char  *target;
	/* NOTE: i_size_ondisk is 64bits, so must hold ->inode_lock to access */
	loff_t i_size_ondisk;         /* physically allocated size */
	loff_t i_size_aligned;          /* block-aligned i_size (used in cont_write_begin) */
	loff_t i_pos;               /* on-disk position of directory entry or 0 */
	struct hlist_node i_hash_fat;    /* hash by i_location */
	struct rw_semaphore truncate_lock; /* protect bmap against truncate */
	struct inode vfs_inode;
};

extern const struct inode_operations exfat_dir_inode_operations;
extern const struct file_operations exfat_dir_operations;
extern const struct inode_operations exfat_symlink_inode_operations;
extern const struct inode_operations exfat_file_inode_operations;
extern const struct file_operations exfat_file_operations; 

/*
 * FIXME : needs on-disk-slot in-memory data
 */

static inline struct exfat_sb_info *EXFAT_SB(struct super_block *sb)
{
	return (struct exfat_sb_info *)sb->s_fs_info;
}

static inline struct exfat_inode_info *EXFAT_I(struct inode *inode)
{
	return container_of(inode, struct exfat_inode_info, vfs_inode);
}

/*
 * If ->i_mode can't hold S_IWUGO (i.e. ATTR_RO), we use ->i_attrs to
 * save ATTR_RO instead of ->i_mode.
 *
 * If it's directory and !sbi->options.rodir, ATTR_RO isn't read-only
 * bit, it's just used as flag for app.
 */
static inline int exfat_mode_can_hold_ro(struct inode *inode)
{
	struct exfat_sb_info *sbi = EXFAT_SB(inode->i_sb);

	if (S_ISDIR(inode->i_mode))
		return 0;

	if ((~sbi->options.fs_fmask) & S_IWUGO)
		return 1;
	return 0;
}

/*
 * FIXME : needs to check symlink option.
 */
/* Convert attribute bits and a mask to the UNIX mode. */
static inline mode_t exfat_make_mode(struct exfat_sb_info *sbi,
		unsigned int attr, mode_t mode)
{
	if ((attr & ATTR_READONLY) && !(attr & ATTR_SUBDIR))
		mode &= ~S_IWUGO;

	if (attr & ATTR_SUBDIR)
		return (mode & ~sbi->options.fs_dmask) | S_IFDIR;
	else if (attr & ATTR_SYMLINK)
		return (mode & ~sbi->options.fs_dmask) | S_IFLNK;

	return (mode & ~sbi->options.fs_fmask) | S_IFREG;
}

/* Return the FAT attribute byte for this inode */
static inline unsigned int exfat_make_attr(struct inode *inode)
{
	unsigned int attrs = EXFAT_I(inode)->fid.attr;

	if (S_ISDIR(inode->i_mode))
		attrs |= ATTR_SUBDIR;
	if (exfat_mode_can_hold_ro(inode) && !(inode->i_mode & S_IWUGO))
		attrs |= ATTR_READONLY;
	return attrs;
}

static inline void exfat_save_attr(struct inode *inode, unsigned int attr)
{
	if (exfat_mode_can_hold_ro(inode))
		EXFAT_I(inode)->fid.attr = attr & ATTR_RWMASK;
	else
		EXFAT_I(inode)->fid.attr = attr & (ATTR_RWMASK | ATTR_READONLY);
}

/* super.c */
int exfat_set_vol_flags(struct super_block *sb, unsigned short new_flag);
inline void set_sb_dirty(struct super_block *sb);

/* fatent.c */
#define get_next_clus(sb, pclu)     exfat_ent_get(sb, *(pclu), pclu)
#define get_next_clus_safe(sb, pclu)    exfat_ent_get_safe(sb, *(pclu), pclu)

int exfat_alloc_cluster(struct super_block *sb, unsigned int num_alloc, struct exfat_chain *p_chain, int dest);
int exfat_free_cluster(struct super_block *sb, struct exfat_chain *p_chain, int do_relse);
int exfat_ent_get(struct super_block *sb, unsigned int loc, unsigned int *content);
int exfat_ent_set(struct super_block *sb, unsigned int loc, unsigned int content);
int exfat_ent_get_safe(struct super_block *sb, unsigned int loc, unsigned int *content);
int exfat_count_ext_entries(struct super_block *sb, struct exfat_chain *p_dir, int entry, struct exfat_dentry *p_entry);
int exfat_chain_cont_cluster(struct super_block *sb, unsigned int chain, unsigned int len);
struct exfat_entry_set_cache *exfat_get_dentry_set_in_dir(struct super_block *sb,
		struct exfat_chain *p_dir, int entry, unsigned int type, struct exfat_dentry **file_ep);
int exfat_clear_cluster(struct inode *inode, unsigned int clu);
int exfat_find_location(struct super_block *sb, struct exfat_chain *p_dir, int entry, unsigned long long *sector, int *offset);
int exfat_find_last_cluster(struct super_block *sb, struct exfat_chain *p_chain,
		unsigned int *ret_clu);
int exfat_mirror_bhs(struct super_block *sb, unsigned long long sec,
	struct buffer_head *bh);

/* balloc.c */
int exfat_load_alloc_bmp(struct super_block *sb);
void exfat_free_alloc_bmp(struct super_block *sb);
int exfat_set_alloc_bitmap(struct super_block *sb, unsigned int clu);
void exfat_clr_alloc_bitmap(struct super_block *sb, unsigned int clu);
unsigned int exfat_test_alloc_bitmap(struct super_block *sb, unsigned int clu);

/* file.c */
int exfat_file_fsync(struct file *filp, loff_t start, loff_t end, int datasync);

/* namei.c */
extern const struct dentry_operations exfat_dentry_ops;
extern const struct dentry_operations exfat_ci_dentry_ops;
int exfat_setattr(struct dentry *dentry, struct iattr *attr);
int exfat_getattr(const struct path *path, struct kstat *stat,
		unsigned int request_mask, unsigned int query_flags);
int exfat_find_empty_entry(struct inode *inode, struct exfat_chain *p_dir, int num_entries);

/* cache.c */
int exfat_cache_init(void);
void exfat_cache_shutdown(void);
void exfat_cache_init_inode(struct inode *inode);
void exfat_cache_inval_inode(struct inode *inode);
int exfat_get_clus(struct inode *inode, unsigned int cluster, unsigned int *fclus,
		unsigned int *dclus, unsigned int *last_dclus, int allow_eof);
int dcache_lock(struct super_block *sb, unsigned long long sec);
int dcache_unlock(struct super_block *sb, unsigned long long sec);
int dcache_modify(struct super_block *sb, unsigned long long sec);
int fcache_release_all(struct super_block *sb);
int dcache_release_all(struct super_block *sb);
int meta_cache_init(struct super_block *sb);
int meta_cache_shutdown(struct super_block *sb);
int dcache_release(struct super_block *sb, unsigned long long sec);
unsigned char *fcache_getblk(struct super_block *sb, unsigned long long sec);
int fcache_modify(struct super_block *sb, unsigned long long sec);
int dcache_readahead(struct super_block *sb, unsigned long long sec);
unsigned char *dcache_getblk(struct super_block *sb, unsigned long long sec);

/* dir.c */
int exfat_create_dir(struct inode *inode, struct exfat_chain *p_dir,
		struct exfat_uni_name *p_uniname, struct exfat_file_id *fid);
void exfat_get_uniname_from_ext_entry(struct super_block *sb, struct exfat_chain *p_dir, int entry, unsigned short *uniname);
int exfat_count_used_clusters(struct super_block *sb, unsigned int *ret_count);
unsigned int exfat_get_entry_type(struct exfat_dentry *p_entry);
unsigned int exfat_get_entry_attr(struct exfat_dentry *p_entry);
void exfat_set_entry_attr(struct exfat_dentry *p_entry, unsigned int attr);
unsigned char exfat_get_entry_flag(struct exfat_dentry *p_entry);
void exfat_set_entry_flag(struct exfat_dentry *p_entry, unsigned char flags);
unsigned int exfat_get_entry_clu0(struct exfat_dentry *p_entry);
void exfat_set_entry_clu0(struct exfat_dentry *p_entry, unsigned int start_clu);
unsigned long long exfat_get_entry_size(struct exfat_dentry *p_entry);
void exfat_set_entry_size(struct exfat_dentry *p_entry, unsigned long long size);
void exfat_get_entry_time(struct exfat_dentry *p_entry, struct exfat_timestamp *tp, unsigned char mode);
void exfat_set_entry_time(struct exfat_dentry *p_entry, struct exfat_timestamp *tp, unsigned char mode);
int exfat_init_dir_entry(struct super_block *sb, struct exfat_chain *p_dir, int entry, unsigned int type, unsigned int start_clu, unsigned long long size);
int exfat_init_ext_entry(struct super_block *sb, struct exfat_chain *p_dir, int entry, int num_entries,
		struct exfat_uni_name *p_uniname, struct exfat_dos_name *p_dosname);
int exfat_delete_dir_entry(struct super_block *sb, struct exfat_chain *p_dir, int entry, int order, int num_entries);
int update_dir_chksum(struct super_block *sb, struct exfat_chain *p_dir, int entry);
int exfat_update_dir_chksum_with_entry_set(struct super_block *sb, struct exfat_entry_set_cache *es);
void exfat_release_dentry_set(struct exfat_entry_set_cache *es);
int exfat_get_num_entries_and_dos_name(struct super_block *sb, struct exfat_chain *p_dir,
		struct exfat_uni_name *p_uniname, int *entries,
		struct exfat_dos_name *p_dosname, int lookup);
int exfat_find_dir_entry(struct super_block *sb, struct exfat_file_id *fid,
		struct exfat_chain *p_dir, struct exfat_uni_name *p_uniname, int num_entries, struct exfat_dos_name *unused, unsigned int type);
int exfat_zeroed_cluster(struct super_block *sb, unsigned long long blknr,
	unsigned long long num_secs);

/* inode.c */
int exfat_sync_inode(struct inode *inode);
struct inode *exfat_build_inode(struct super_block *sb, const struct exfat_file_id *fid,
		loff_t i_pos);
struct exfat_dentry *exfat_get_dentry_in_dir(struct super_block *sb, struct exfat_chain *p_dir, int entry, unsigned long long *sector);
void exfat_attach(struct inode *inode, loff_t i_pos);
void exfat_detach(struct inode *inode);
void exfat_truncate(struct inode *inode, loff_t old_size);
struct inode *exfat_iget(struct super_block *sb, loff_t i_pos);
int exfat_write_inode(struct inode *inode, struct writeback_control *wbc);
struct inode *exfat_alloc_inode(struct super_block *sb);
void exfat_destroy_inode(struct inode *inode);
void exfat_evict_inode(struct inode *inode);
int exfat_read_inode(struct inode *inode, struct exfat_dir_entry *info);

/* exfat/nls.c */
/* NLS management function */
int  nls_cmp_sfn(struct super_block *sb, unsigned char *a, unsigned char *b);
int  nls_cmp_uniname(struct super_block *sb, unsigned short *a, unsigned short *b);
int  nls_uni16s_to_sfn(struct super_block *sb, struct exfat_uni_name *p_uniname, struct exfat_dos_name *p_dosname, int *p_lossy);
int  nls_sfn_to_uni16s(struct super_block *sb, struct exfat_dos_name *p_dosname, struct exfat_uni_name *p_uniname);
int  nls_uni16s_to_vfsname(struct super_block *sb, struct exfat_uni_name *uniname, unsigned char *p_cstring, int len);
int  nls_vfsname_to_uni16s(struct super_block *sb, const unsigned char *p_cstring,
		const int len, struct exfat_uni_name *uniname, int *p_lossy);

/* exfat/misc.c */
	extern void
__exfat_fs_error(struct super_block *sb, int report, const char *fmt, ...)
	__printf(3, 4) __cold;
#define exfat_fs_error(sb, fmt, args...)          \
		__exfat_fs_error(sb, 1, fmt, ## args)
#define exfat_fs_error_ratelimit(sb, fmt, args...) \
		__exfat_fs_error(sb, __ratelimit(&EXFAT_SB(sb)->ratelimit), fmt, ## args)
	extern void
exfat_msg(struct super_block *sb, const char *lv, const char *fmt, ...)
	__printf(3, 4) __cold;
	extern void exfat_time_fat2unix(struct exfat_sb_info *sbi, struct timespec64 *ts,
			struct exfat_date_time *tp);
extern void exfat_time_unix2fat(struct exfat_sb_info *sbi, struct timespec64 *ts,
		struct exfat_date_time *tp);
extern struct exfat_timestamp *tm_now(struct exfat_sb_info *sbi, struct exfat_timestamp *tm);

unsigned short calc_chksum_2byte(void *data, int len, unsigned short chksum, int type);
#endif /* !_EXFAT_H */

