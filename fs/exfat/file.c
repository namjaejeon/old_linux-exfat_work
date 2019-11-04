// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include "exfat_raw.h"
#include "exfat_fs.h"

const struct file_operations exfat_file_operations = {
	.llseek      = generic_file_llseek,
	.read_iter   = generic_file_read_iter,
	.write_iter  = generic_file_write_iter,
	.mmap        = generic_file_mmap,
	.fsync       = generic_file_fsync,
	.splice_read = generic_file_splice_read,
};

const struct inode_operations exfat_file_inode_operations = {
	.setattr     = exfat_setattr,
	.getattr     = exfat_getattr,
};
