// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include "exfat_raw.h"
#include "exfat_fs.h"

static int exfat_file_release(struct inode *inode, struct file *filp)
{
	struct super_block *sb = inode->i_sb;

	EXFAT_I(inode)->fid->size = i_size_read(inode);
	if (exfat_set_vol_flags(sb, VOL_CLEAN))
		return -EIO;
	return 0;
}

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
	.release     = exfat_file_release,
	.fsync       = exfat_file_fsync,
	.splice_read = generic_file_splice_read,
};

static const char *exfat_follow_link(struct dentry *dentry, struct inode *inode,
		struct delayed_call *done)
{
	struct exfat_inode_info *ei = EXFAT_I(inode);

	return ei->target;
}

const struct inode_operations exfat_symlink_inode_operations = {
	.get_link = exfat_follow_link,
};

const struct inode_operations exfat_file_inode_operations = {
	.setattr     = exfat_setattr,
	.getattr     = exfat_getattr,
};
