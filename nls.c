// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/string.h>
#include <linux/nls.h>

#include "exfat_raw.h"
#include "exfat_fs.h"
#include "upcase.h"

static unsigned short bad_dos_chars[] = {
	/* + , ; = [ ] */
	0x002B, 0x002C, 0x003B, 0x003D, 0x005B, 0x005D,
	0xFF0B, 0xFF0C, 0xFF1B, 0xFF1D, 0xFF3B, 0xFF3D,
	0
};

/*
 * Allow full-width illegal characters :
 * "MS windows 7" supports full-width-invalid-name-characters.
 * So we should check half-width-invalid-name-characters(ASCII) only
 * for compatibility.
 *
 * " * / : < > ? \ |
 *
 * patch 1.2.0
 */
static unsigned short bad_uni_chars[] = {
	0x0022,         0x002A, 0x002F, 0x003A,
	0x003C, 0x003E, 0x003F, 0x005C, 0x007C,
	0
};

static int convert_ch_to_uni(struct nls_table *nls, unsigned char *ch,
		unsigned short *uni, int *lossy)
{
	int len;

	*uni = 0x0;

	if (ch[0] < 0x80) {
		*uni = (unsigned short) ch[0];
		return 1;
	}

	len = nls->char2uni(ch, MAX_CHARSET_SIZE, uni);
	if (len < 0) {
		/* conversion failed */
		if (lossy != NULL)
			*lossy |= NLS_NAME_LOSSY;
		*uni = (unsigned short) '_';
		if (!strcmp(nls->charset, "utf8"))
			return 1;
		return 2;
	}

	return len;
}

static int convert_uni_to_ch(struct nls_table *nls, unsigned short uni,
		unsigned char *ch, int *lossy)
{
	int len;

	ch[0] = 0x0;

	if (uni < 0x0080) {
		ch[0] = (unsigned char) uni;
		return 1;
	}

	len = nls->uni2char(uni, ch, MAX_CHARSET_SIZE);
	if (len < 0) {
		/* conversion failed */
		if (lossy != NULL)
			*lossy |= NLS_NAME_LOSSY;
		ch[0] = '_';
		return 1;
	}

	return len;
}

static unsigned short nls_upper(struct super_block *sb, unsigned short a)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	if (EXFAT_SB(sb)->options.casesensitive)
		return a;
	if ((sbi->vol_utbl)[get_col_index(a)] != NULL)
		return (sbi->vol_utbl)[get_col_index(a)][get_row_index(a)];
	else
		return a;
}

unsigned short *nls_wstrchr(unsigned short *str, unsigned short wchar)
{
	while (*str) {
		if (*(str++) == wchar)
			return str;
	}

	return 0;
}

int nls_cmp_sfn(struct super_block *sb, unsigned char *a, unsigned char *b)
{
	return strncmp((void *)a, (void *)b, DOS_NAME_LENGTH);
}

int nls_cmp_uniname(struct super_block *sb, unsigned short *a,
		unsigned short *b)
{
	int i;

	for (i = 0; i < MAX_NAME_LENGTH; i++, a++, b++) {
		if (nls_upper(sb, *a) != nls_upper(sb, *b))
			return 1;
		if (*a == 0x0)
			return 0;
	}
	return 0;
}

#define CASE_LOWER_BASE (0x08)	/* base is lower case */
#define CASE_LOWER_EXT  (0x10)	/* extension is lower case */

int nls_uni16s_to_sfn(struct super_block *sb, struct exfat_uni_name *p_uniname,
		struct exfat_dos_name *p_dosname, int *p_lossy)
{
	int i, j, len, lossy = NLS_NAME_NO_LOSSY;
	unsigned char buf[MAX_CHARSET_SIZE];
	unsigned char lower = 0, upper = 0;
	unsigned char *dosname = p_dosname->name;
	unsigned short *uniname = p_uniname->name;
	unsigned short *p, *last_period;
	struct nls_table *nls = EXFAT_SB(sb)->nls_disk;

	/* DOSNAME is filled with space */
	for (i = 0; i < DOS_NAME_LENGTH; i++)
		*(dosname+i) = ' ';

	/* DOT and DOTDOT are handled by VFS layer */

	/* search for the last embedded period */
	last_period = NULL;
	for (p = uniname; *p; p++) {
		if (*p == (unsigned short) '.')
			last_period = p;
	}

	i = 0;
	while (i < DOS_NAME_LENGTH) {
		if (i == 8) {
			if (last_period == NULL)
				break;

			if (uniname <= last_period) {
				if (uniname < last_period)
					lossy |= NLS_NAME_OVERLEN;
				uniname = last_period + 1;
			}
		}

		if (*uniname == (unsigned short) '\0') {
			break;
		} else if (*uniname == (unsigned short) ' ') {
			lossy |= NLS_NAME_LOSSY;
		} else if (*uniname == (unsigned short) '.') {
			if (uniname < last_period)
				lossy |= NLS_NAME_LOSSY;
			else
				i = 8;
		} else if (nls_wstrchr(bad_dos_chars, *uniname)) {
			lossy |= NLS_NAME_LOSSY;
			*(dosname+i) = '_';
			i++;
		} else {
			len = convert_uni_to_ch(nls, *uniname, buf, &lossy);

			if (len > 1) {
				if ((i >= 8) && ((i+len) > DOS_NAME_LENGTH))
					break;

				if ((i <  8) && ((i+len) > 8)) {
					i = 8;
					continue;
				}

				lower = 0xFF;

				for (j = 0; j < len; j++, i++)
					*(dosname+i) = *(buf+j);
			} else { /* len == 1 */
				if ((*buf >= 'a') && (*buf <= 'z')) {
					*(dosname+i) = *buf - ('a' - 'A');

					lower |= (i < 8) ?
						CASE_LOWER_BASE :
						CASE_LOWER_EXT;
				} else if ((*buf >= 'A') && (*buf <= 'Z')) {
					*(dosname+i) = *buf;

					upper |= (i < 8) ?
						CASE_LOWER_BASE :
						CASE_LOWER_EXT;
				} else {
					*(dosname+i) = *buf;
				}
				i++;
			}
		}

		uniname++;
	}

	if (*dosname == 0xE5)
		*dosname = 0x05;
	if (*uniname != 0x0)
		lossy |= NLS_NAME_OVERLEN;

	if (upper & lower)
		p_dosname->name_case = 0xFF;
	else
		p_dosname->name_case = lower;

	if (p_lossy)
		*p_lossy = lossy;
	return i;
}

int nls_sfn_to_uni16s(struct super_block *sb, struct exfat_dos_name *p_dosname,
		struct exfat_uni_name *p_uniname)
{
	int i = 0, j, n = 0;
	unsigned char buf[MAX_DOSNAME_BUF_SIZE];
	unsigned char *dosname = p_dosname->name;
	unsigned short *uniname = p_uniname->name;
	struct nls_table *nls = EXFAT_SB(sb)->nls_disk;

	if (*dosname == 0x05) {
		*buf = 0xE5;
		i++;
		n++;
	}

	for ( ; i < 8; i++, n++) {
		if (*(dosname+i) == ' ')
			break;

		if ((*(dosname+i) >= 'A') && (*(dosname+i) <= 'Z') &&
				(p_dosname->name_case & CASE_LOWER_BASE))
			*(buf+n) = *(dosname+i) + ('a' - 'A');
		else
			*(buf+n) = *(dosname+i);
	}
	if (*(dosname+8) != ' ') {
		*(buf+n) = '.';
		n++;
	}

	for (i = 8; i < DOS_NAME_LENGTH; i++, n++) {
		if (*(dosname+i) == ' ')
			break;

		if ((*(dosname+i) >= 'A') && (*(dosname+i) <= 'Z') &&
			       (p_dosname->name_case & CASE_LOWER_EXT))
			*(buf+n) = *(dosname+i) + ('a' - 'A');
		else
			*(buf+n) = *(dosname+i);
	}
	*(buf+n) = '\0';

	i = j = 0;
	while (j < MAX_NAME_LENGTH) {
		if (*(buf+i) == '\0')
			break;

		i += convert_ch_to_uni(nls, (buf+i), uniname, NULL);

		uniname++;
		j++;
	}

	*uniname = (unsigned short) '\0';
	return j;
}

static int __nls_utf16s_to_vfsname(struct super_block *sb,
		struct exfat_uni_name *p_uniname, unsigned char *p_cstring,
		int buflen)
{
	int len;
	const unsigned short *uniname = p_uniname->name;

	/* always len >= 0 */
	len = utf16s_to_utf8s(uniname, MAX_NAME_LENGTH, UTF16_HOST_ENDIAN,
		p_cstring, buflen);
	p_cstring[len] = '\0';
	return len;
}

static int __nls_vfsname_to_utf16s(struct super_block *sb,
		const unsigned char *p_cstring, const int len,
		struct exfat_uni_name *p_uniname, int *p_lossy)
{
	int i, unilen, lossy = NLS_NAME_NO_LOSSY;
	unsigned short upname[MAX_NAME_LENGTH + 1];
	unsigned short *uniname = p_uniname->name;

	WARN_ON(!len);

	unilen = utf8s_to_utf16s(p_cstring, len, UTF16_HOST_ENDIAN,
			(wchar_t *)uniname, MAX_NAME_LENGTH+2);
	if (unilen < 0) {
		exfat_msg(sb, KERN_ERR,
			"failed to vfsname_to_utf16(err : %d) vfsnamelen : %d",
			unilen, len);
		return unilen;
	}

	if (unilen > MAX_NAME_LENGTH) {
		exfat_msg(sb, KERN_ERR,
			"failed to vfsname_to_utf16(estr:ENAMETOOLONG) vfsnamelen : %d, unilen : %d > %d",
			len, unilen, MAX_NAME_LENGTH);
		return -ENAMETOOLONG;
	}

	p_uniname->name_len = (unsigned char)(unilen & 0xFF);

	for (i = 0; i < unilen; i++) {
		if ((*uniname < 0x0020) || nls_wstrchr(bad_uni_chars, *uniname))
			lossy |= NLS_NAME_LOSSY;

		*(upname+i) = nls_upper(sb, *uniname);
		uniname++;
	}

	*uniname = (unsigned short)'\0';
	p_uniname->name_len = unilen;
	p_uniname->name_hash = exfat_calc_chksum_2byte((void *) upname,
				unilen << 1, 0, CS_DEFAULT);

	if (p_lossy)
		*p_lossy = lossy;

	return unilen;
}

static int __nls_uni16s_to_vfsname(struct super_block *sb,
		struct exfat_uni_name *p_uniname, unsigned char *p_cstring,
		int buflen)
{
	int i, j, len, out_len = 0;
	unsigned char buf[MAX_CHARSET_SIZE];
	const unsigned short *uniname = p_uniname->name;
	struct nls_table *nls = EXFAT_SB(sb)->nls_io;

	i = 0;
	while ((i < MAX_NAME_LENGTH) && (out_len < (buflen - 1))) {
		if (*uniname == (unsigned short)'\0')
			break;

		len = convert_uni_to_ch(nls, *uniname, buf, NULL);

		if (out_len + len >= buflen)
			len = (buflen - 1) - out_len;

		out_len += len;

		if (len > 1) {
			for (j = 0; j < len; j++)
				*p_cstring++ = *(buf+j);
		} else { /* len == 1 */
			*p_cstring++ = *buf;
		}

		uniname++;
		i++;
	}

	*p_cstring = '\0';
	return out_len;
}

static int __nls_vfsname_to_uni16s(struct super_block *sb,
		const unsigned char *p_cstring, const int len,
		struct exfat_uni_name *p_uniname, int *p_lossy)
{
	int i, unilen, lossy = NLS_NAME_NO_LOSSY;
	unsigned short upname[MAX_NAME_LENGTH + 1];
	unsigned short *uniname = p_uniname->name;
	struct nls_table *nls = EXFAT_SB(sb)->nls_io;

	WARN_ON(!len);

	i = unilen = 0;
	while ((unilen < MAX_NAME_LENGTH) && (i < len)) {
		i += convert_ch_to_uni(nls, (unsigned char *)(p_cstring+i),
			uniname, &lossy);

		if ((*uniname < 0x0020) || nls_wstrchr(bad_uni_chars, *uniname))
			lossy |= NLS_NAME_LOSSY;

		*(upname+unilen) = nls_upper(sb, *uniname);

		uniname++;
		unilen++;
	}

	if (*(p_cstring+i) != '\0')
		lossy |= NLS_NAME_OVERLEN;

	*uniname = (unsigned short)'\0';
	p_uniname->name_len = unilen;
	p_uniname->name_hash = exfat_calc_chksum_2byte((void *) upname,
		unilen << 1, 0, CS_DEFAULT);

	if (p_lossy)
		*p_lossy = lossy;

	return unilen;
}

int nls_uni16s_to_vfsname(struct super_block *sb,
		struct exfat_uni_name *uniname, unsigned char *p_cstring,
		int buflen)
{
	if (EXFAT_SB(sb)->options.utf8)
		return __nls_utf16s_to_vfsname(sb, uniname, p_cstring, buflen);

	return __nls_uni16s_to_vfsname(sb, uniname, p_cstring, buflen);
}

int nls_vfsname_to_uni16s(struct super_block *sb,
		const unsigned char *p_cstring, const int len,
		struct exfat_uni_name *uniname, int *p_lossy)
{
	if (EXFAT_SB(sb)->options.utf8)
		return __nls_vfsname_to_utf16s(sb, p_cstring, len, uniname,
				p_lossy);
	return __nls_vfsname_to_uni16s(sb, p_cstring, len, uniname, p_lossy);
}
