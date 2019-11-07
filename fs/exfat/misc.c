// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Written 1992,1993 by Werner Almesberger
 *  22/11/2000 - Fixed fat_date_unix2dos for dates earlier than 01/01/1980
 *		 and date_dos2unix for date==0 by Igor Zhbanov(bsg@uniyar.ac.ru)
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/time.h>
#include <linux/fs.h>

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

/* <linux/time.h> externs sys_tz
 * extern struct timezone sys_tz;
 */
#define UNIX_SECS_1980    315532800L

#if BITS_PER_LONG == 64
#define UNIX_SECS_2108    4354819200L
#endif

/* days between 1970/01/01 and 1980/01/01 (2 leap days) */
#define DAYS_DELTA_DECADE    (365 * 10 + 2)
/* 120 (2100 - 1980) isn't leap year */
#define NO_LEAP_YEAR_2100    (120)
#define IS_LEAP_YEAR(y)    (!((y) & 0x3) && (y) != NO_LEAP_YEAR_2100)

#define SECS_PER_MIN    (60)
#define SECS_PER_HOUR   (60 * SECS_PER_MIN)
#define SECS_PER_DAY    (24 * SECS_PER_HOUR)

#define MAKE_LEAP_YEAR(leap_year, year)                         \
	do {                                                    \
		/* 2100 isn't leap year */                      \
		if (unlikely(year > NO_LEAP_YEAR_2100))         \
			leap_year = ((year + 3) / 4) - 1;       \
		else                                            \
			leap_year = ((year + 3) / 4);           \
	} while (0)

/* Linear day numbers of the respective 1sts in non-leap years. */
static time_t accum_days_in_year[] = {
	/* Month : N 01  02  03  04  05  06  07  08  09  10  11  12 */
	0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 0, 0, 0,
};

/* Convert a FAT time/date pair to a UNIX date (seconds since 1 1 70). */
void exfat_time_fat2unix(struct exfat_sb_info *sbi, struct timespec64 *ts,
		struct exfat_date_time *tp)
{
	time_t year = tp->year;
	time_t ld; /* leap day */

	MAKE_LEAP_YEAR(ld, year);

	if (IS_LEAP_YEAR(year) && (tp->month) > 2)
		ld++;

	ts->tv_sec =  tp->second  + tp->minute * SECS_PER_MIN
			+ tp->hour * SECS_PER_HOUR
			+ (year * 365 + ld + accum_days_in_year[tp->month]
			+ (tp->day - 1) + DAYS_DELTA_DECADE) * SECS_PER_DAY;

	if (!sbi->options.tz_utc)
		ts->tv_sec += sys_tz.tz_minuteswest * SECS_PER_MIN;

	ts->tv_nsec = 0;
}

/* Convert linear UNIX date to a FAT time/date pair. */
void exfat_time_unix2fat(struct exfat_sb_info *sbi, struct timespec64 *ts,
		struct exfat_date_time *tp)
{
	time_t second = ts->tv_sec;
	time_t day, month, year;
	time_t ld; /* leap day */

	if (!sbi->options.tz_utc)
		second -= sys_tz.tz_minuteswest * SECS_PER_MIN;

	/* Jan 1 GMT 00:00:00 1980. But what about another time zone? */
	if (second < UNIX_SECS_1980) {
		tp->second  = 0;
		tp->minute  = 0;
		tp->hour = 0;
		tp->day  = 1;
		tp->month  = 1;
		tp->year = 0;
		return;
	}
#if (BITS_PER_LONG == 64)
	if (second >= UNIX_SECS_2108) {
		tp->second  = 59;
		tp->minute  = 59;
		tp->hour = 23;
		tp->day  = 31;
		tp->month  = 12;
		tp->year = 127;
		return;
	}
#endif

	day = second / SECS_PER_DAY - DAYS_DELTA_DECADE;
	year = day / 365;

	MAKE_LEAP_YEAR(ld, year);
	if (year * 365 + ld > day)
		year--;

	MAKE_LEAP_YEAR(ld, year);
	day -= year * 365 + ld;

	if (IS_LEAP_YEAR(year) && day == accum_days_in_year[3]) {
		month = 2;
	} else {
		if (IS_LEAP_YEAR(year) && day > accum_days_in_year[3])
			day--;
		for (month = 1; month < 12; month++) {
			if (accum_days_in_year[month + 1] > day)
				break;
		}
	}
	day -= accum_days_in_year[month];

	tp->second  = second % SECS_PER_MIN;
	tp->minute  = (second / SECS_PER_MIN) % 60;
	tp->hour = (second / SECS_PER_HOUR) % 24;
	tp->day  = day + 1;
	tp->month  = month;
	tp->year = year;
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
