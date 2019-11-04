// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include "exfat_raw.h"
#include "exfat_fs.h"

static int exfat_file_mmap(struct file *file, struct vm_area_struct *vm_struct)
{
	return generic_file_mmap(file, vm_struct);
}

int exfat_file_fsync(struct file *filp, loff_t start, loff_t end, int datasync)
{
	return generic_file_fsync(filp, start, end, datasync);
}

const struct file_operations exfat_file_operations = {
	.llseek      = generic_file_llseek,
	.read_iter   = generic_file_read_iter,
	.write_iter  = generic_file_write_iter,
	.mmap        = exfat_file_mmap,
	.fsync       = exfat_file_fsync,
	.splice_read = generic_file_splice_read,
};

const struct inode_operations exfat_file_inode_operations = {
	.setattr     = exfat_setattr,
	.getattr     = exfat_getattr,
};
