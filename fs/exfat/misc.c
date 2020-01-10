// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Written 1992,1993 by Werner Almesberger
 *  22/11/2000 - Fixed fat_date_unix2dos for dates earlier than 01/01/1980
 *		 and date_dos2unix for date==0 by Igor Zhbanov(bsg@uniyar.ac.ru)
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/buffer_head.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

/*
 * exfat_fs_error reports a file system problem that might indicate fa data
 * corruption/inconsistency. Depending on 'errors' mount option the
 * panic() is called, or error message is printed FAT and nothing is done,
 * or filesystem is remounted read-only (default behavior).
 * In case the file system is remounted read-only, it can be made writable
 * again by remounting it.
 */
void __exfat_fs_error(struct super_block *sb, int report, const char *fmt, ...)
{
	struct exfat_mount_options *opts = &EXFAT_SB(sb)->options;
	va_list args;
	struct va_format vaf;

	if (report) {
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		exfat_msg(sb, KERN_ERR, "error, %pV\n", &vaf);
		va_end(args);
	}

	if (opts->errors == EXFAT_ERRORS_PANIC) {
		panic("exFAT-fs (%s): fs panic from previous error\n",
			sb->s_id);
	} else if (opts->errors == EXFAT_ERRORS_RO && !sb_rdonly(sb)) {
		sb->s_flags |= SB_RDONLY;
		exfat_msg(sb, KERN_ERR, "Filesystem has been set read-only");
	}
}

/*
 * exfat_msg() - print preformated EXFAT specific messages.
 * All logs except what uses exfat_fs_error() should be written by exfat_msg()
 */
void exfat_msg(struct super_block *sb, const char *level, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	/* level means KERN_ pacility level */
	printk("%sexFAT-fs (%s): %pV\n", level, sb->s_id, &vaf);
	va_end(args);
}

void exfat_time_min(struct exfat_date_time *tp)
{
	tp->milli_second = 0;
	tp->second = 0;
	tp->minute = 0;
	tp->hour = 0;
	tp->day = 1;
	tp->month = 1;
	tp->year = 0;
}

void exfat_time_max(struct exfat_date_time *tp)
{
	tp->milli_second = 999;
	tp->second = 59;
	tp->minute = 59;
	tp->hour = 23;
	tp->day = 31;
	tp->month = 12;
	tp->year = 127;
}

#define UNIX_SECS_1980    315532800L
#define UNIX_SECS_2108    4354819200LL

#define SECS_PER_MIN    (60)
#define TIMEZONE_SEC(x)	((x) * 15 * SECS_PER_MIN)

static void exfat_adjust_tz(struct timespec64 *ts, u8 tz_off)
{
	/* Treat as UTC time, but need to adjust timezone to UTC0 */
	if (tz_off <= 0x3F)
		ts->tv_sec -= TIMEZONE_SEC(tz_off);
	else /* 0x40 <= (tz_off & 0x7F) <=0x7F */
		ts->tv_sec += TIMEZONE_SEC(0x80 - tz_off);
}

/* Convert a FAT time/date pair to a UNIX date (seconds since 1 1 70). */
void exfat_time_fat2unix(struct exfat_sb_info *sbi, struct timespec64 *ts,
		struct exfat_date_time *tp)
{
	ts->tv_sec = mktime64(tp->year + 1980, tp->month, tp->day,
			tp->hour, tp->minute, tp->second);
	ts->tv_nsec = tp->milli_second * NSEC_PER_MSEC;

	if (tp->timezone & EXFAT_TZ_VALID)
		exfat_adjust_tz(ts, tp->timezone & ~EXFAT_TZ_VALID);
	else
		; /* Treat as local time */
}


static inline int exfat_tz_offset(struct exfat_sb_info *sbi)
{
	return ((sbi->options.time_offset ?
		sbi->options.time_offset :
		sys_tz.tz_minuteswest) / -15) & 0x7F;
}

/* Convert linear UNIX date to a FAT time/date pair. */
void exfat_time_unix2fat(struct exfat_sb_info *sbi, struct timespec64 *ts,
		struct exfat_date_time *tp)
{
	time64_t second = ts->tv_sec;
	struct tm tm;

	time64_to_tm(second, 0, &tm);

	tp->timezone = exfat_tz_offset(sbi) | EXFAT_TZ_VALID;

	/* Jan 1 GMT 00:00:00 1980. But what about another time zone? */
	if (second < UNIX_SECS_1980) {
		exfat_time_min(tp);
		return;
	}

	if (second >= UNIX_SECS_2108) {
		exfat_time_max(tp);
		return;
	}

	tp->milli_second = ts->tv_nsec / NSEC_PER_MSEC;
	tp->second = tm.tm_sec;
	tp->minute = tm.tm_min;
	tp->hour = tm.tm_hour;
	tp->day = tm.tm_mday;
	tp->month = tm.tm_mon + 1;
	tp->year = tm.tm_year + 1900 - 1980;
}

struct exfat_timestamp *exfat_tm_now(struct exfat_sb_info *sbi,
		struct exfat_timestamp *tp)
{
	struct timespec64 ts;
	struct exfat_date_time dt;

	ktime_get_real_ts64(&ts);
	exfat_time_unix2fat(sbi, &ts, &dt);

	tp->year = dt.year;
	tp->mon = dt.month;
	tp->day = dt.day;
	tp->hour = dt.hour;
	tp->min = dt.minute;
	tp->sec = dt.second;
	tp->tz = dt.timezone;

	return tp;
}

unsigned short exfat_calc_chksum_2byte(void *data, int len,
		unsigned short chksum, int type)
{
	int i;
	unsigned char *c = (unsigned char *)data;

	for (i = 0; i < len; i++, c++) {
		if (((i == 2) || (i == 3)) && (type == CS_DIR_ENTRY))
			continue;
		chksum = (((chksum & 1) << 15) | ((chksum & 0xFFFE) >> 1)) +
			(unsigned short)*c;
	}
	return chksum;
}

void exfat_update_bh(struct super_block *sb, struct buffer_head *bh, int sync)
{
	set_bit(EXFAT_SB_DIRTY, &EXFAT_SB(sb)->s_state);
	set_buffer_uptodate(bh);
	mark_buffer_dirty(bh);

	if (sync)
		sync_dirty_buffer(bh);
}

void exfat_chain_set(struct exfat_chain *ec, unsigned int dir,
		unsigned int size, unsigned char flags)
{
	ec->dir = dir;
	ec->size = size;
	ec->flags = flags;
}

void exfat_chain_dup(struct exfat_chain *dup, struct exfat_chain *ec)
{
	return exfat_chain_set(dup, ec->dir, ec->size, ec->flags);
}
