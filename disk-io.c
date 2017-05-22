#include "/var/tmp/sensor.h"
/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include "kerncompat.h"
#include "radix-tree.h"
#include "ctree.h"
#include "disk-io.h"
#include "volumes.h"
#include "transaction.h"
#include "crc32c.h"
#include "utils.h"
#include "print-tree.h"
#include "rbtree-utils.h"

/* specified errno for check_tree_block */
#define BTRFS_BAD_BYTENR		(-1)
#define BTRFS_BAD_FSID			(-2)
#define BTRFS_BAD_LEVEL			(-3)
#define BTRFS_BAD_NRITEMS		(-4)

/* Calculate max possible nritems for a leaf/node */
static u32 max_nritems(u8 level, u32 nodesize)
{

	Din_Go(14477,7);if (level == 0)
		{/*1*/{u32  ReplaceReturn4287 = ((nodesize - sizeof(struct btrfs_header)) /
			sizeof(struct btrfs_item)); Din_Go(14478,7); return ReplaceReturn4287;};/*2*/}
	{u32  ReplaceReturn4286 = ((nodesize - sizeof(struct btrfs_header)) /
		sizeof(struct btrfs_key_ptr)); Din_Go(14479,7); return ReplaceReturn4286;};
}

static int check_tree_block(struct btrfs_fs_info *fs_info,
			    struct extent_buffer *buf)
{

	Din_Go(14480,7);struct btrfs_fs_devices *fs_devices;
	u32 leafsize = btrfs_super_leafsize(fs_info->super_copy);
	int ret = BTRFS_BAD_FSID;

	Din_Go(14482,7);if (buf->start != btrfs_header_bytenr(buf))
		{/*3*/{int  ReplaceReturn4285 = BTRFS_BAD_BYTENR; Din_Go(14481,7); return ReplaceReturn4285;};/*4*/}
	Din_Go(14484,7);if (btrfs_header_level(buf) >= BTRFS_MAX_LEVEL)
		{/*5*/{int  ReplaceReturn4284 = BTRFS_BAD_LEVEL; Din_Go(14483,7); return ReplaceReturn4284;};/*6*/}
	Din_Go(14486,7);if (btrfs_header_nritems(buf) > max_nritems(btrfs_header_level(buf),
						    leafsize))
		{/*7*/{int  ReplaceReturn4283 = BTRFS_BAD_NRITEMS; Din_Go(14485,7); return ReplaceReturn4283;};/*8*/}

	Din_Go(14487,7);fs_devices = fs_info->fs_devices;
	Din_Go(14492,7);while (fs_devices) {
		Din_Go(14488,7);if (fs_info->ignore_fsid_mismatch ||
		    !memcmp_extent_buffer(buf, fs_devices->fsid,
					  btrfs_header_fsid(),
					  BTRFS_FSID_SIZE)) {
			Din_Go(14489,7);ret = 0;
			Din_Go(14490,7);break;
		}
		Din_Go(14491,7);fs_devices = fs_devices->seed;
	}
	{int  ReplaceReturn4282 = ret; Din_Go(14493,7); return ReplaceReturn4282;};
}

static void print_tree_block_error(struct btrfs_fs_info *fs_info,
				struct extent_buffer *eb,
				int err)
{
	Din_Go(14494,7);char fs_uuid[BTRFS_UUID_UNPARSED_SIZE] = {'\0'};
	char found_uuid[BTRFS_UUID_UNPARSED_SIZE] = {'\0'};
	u8 buf[BTRFS_UUID_SIZE];

	Din_Go(14503,7);switch (err) {
	case BTRFS_BAD_FSID:
		Din_Go(14495,7);read_extent_buffer(eb, buf, btrfs_header_fsid(),
				   BTRFS_UUID_SIZE);
		uuid_unparse(buf, found_uuid);
		uuid_unparse(fs_info->fsid, fs_uuid);
		fprintf(stderr, "fsid mismatch, want=%s, have=%s\n",
			fs_uuid, found_uuid);
		Din_Go(14496,7);break;
	case BTRFS_BAD_BYTENR:
		Din_Go(14497,7);fprintf(stderr, "bytenr mismatch, want=%llu, have=%llu\n",
			eb->start, btrfs_header_bytenr(eb));
		Din_Go(14498,7);break;
	case BTRFS_BAD_LEVEL:
		Din_Go(14499,7);fprintf(stderr, "bad level, %u > %u\n",
			btrfs_header_level(eb), BTRFS_MAX_LEVEL);
		Din_Go(14500,7);break;
	case BTRFS_BAD_NRITEMS:
		Din_Go(14501,7);fprintf(stderr, "invalid nr_items: %u\n",
			btrfs_header_nritems(eb));
		Din_Go(14502,7);break;
	}Din_Go(14504,7);
}

u32 btrfs_csum_data(struct btrfs_root *root, char *data, u32 seed, size_t len)
{
	{u32  ReplaceReturn4281 = crc32c(seed, data, len); Din_Go(14505,7); return ReplaceReturn4281;};
}

void btrfs_csum_final(u32 crc, char *result)
{
	Din_Go(14506,7);*(__le32 *)result = ~cpu_to_le32(crc);Din_Go(14507,7);
}

static int __csum_tree_block_size(struct extent_buffer *buf, u16 csum_size,
				  int verify, int silent)
{
	Din_Go(14508,7);char result[BTRFS_CSUM_SIZE];
	u32 len;
	u32 crc = ~(u32)0;

	len = buf->len - BTRFS_CSUM_SIZE;
	crc = crc32c(crc, buf->data + BTRFS_CSUM_SIZE, len);
	btrfs_csum_final(crc, result);

	Din_Go(14513,7);if (verify) {
		Din_Go(14509,7);if (memcmp_extent_buffer(buf, result, 0, csum_size)) {
			Din_Go(14510,7);if (!silent)
				printk("checksum verify failed on %llu found %08X wanted %08X\n",
				       (unsigned long long)buf->start,
				       *((u32 *)result),
				       *((u32*)(char *)buf->data));
			{int  ReplaceReturn4280 = 1; Din_Go(14511,7); return ReplaceReturn4280;};
		}
	} else {
		Din_Go(14512,7);write_extent_buffer(buf, result, 0, csum_size);
	}
	{int  ReplaceReturn4279 = 0; Din_Go(14514,7); return ReplaceReturn4279;};
}

int csum_tree_block_size(struct extent_buffer *buf, u16 csum_size, int verify)
{
	{int  ReplaceReturn4278 = __csum_tree_block_size(buf, csum_size, verify, 0); Din_Go(14515,7); return ReplaceReturn4278;};
}

int verify_tree_block_csum_silent(struct extent_buffer *buf, u16 csum_size)
{
	{int  ReplaceReturn4277 = __csum_tree_block_size(buf, csum_size, 1, 1); Din_Go(14516,7); return ReplaceReturn4277;};
}

static int csum_tree_block_fs_info(struct btrfs_fs_info *fs_info,
				   struct extent_buffer *buf, int verify)
{
	Din_Go(14517,7);u16 csum_size =
		btrfs_super_csum_size(fs_info->super_copy);
	Din_Go(14519,7);if (verify && fs_info->suppress_check_block_errors)
		{/*9*/{int  ReplaceReturn4276 = verify_tree_block_csum_silent(buf, csum_size); Din_Go(14518,7); return ReplaceReturn4276;};/*10*/}
	{int  ReplaceReturn4275 = csum_tree_block_size(buf, csum_size, verify); Din_Go(14520,7); return ReplaceReturn4275;};
}

int csum_tree_block(struct btrfs_root *root, struct extent_buffer *buf,
			   int verify)
{
	{int  ReplaceReturn4274 = csum_tree_block_fs_info(root->fs_info, buf, verify); Din_Go(14521,7); return ReplaceReturn4274;};
}

struct extent_buffer *btrfs_find_tree_block(struct btrfs_root *root,
					    u64 bytenr, u32 blocksize)
{
	{struct extent_buffer * ReplaceReturn4273 = find_extent_buffer(&root->fs_info->extent_cache,
				  bytenr, blocksize); Din_Go(14522,7); return ReplaceReturn4273;};
}

struct extent_buffer* btrfs_find_create_tree_block(
		struct btrfs_fs_info *fs_info, u64 bytenr, u32 blocksize)
{
	{struct extent_buffer * ReplaceReturn4272 = alloc_extent_buffer(&fs_info->extent_cache, bytenr, blocksize); Din_Go(14523,7); return ReplaceReturn4272;};
}

void readahead_tree_block(struct btrfs_root *root, u64 bytenr, u32 blocksize,
			  u64 parent_transid)
{
	Din_Go(14524,7);struct extent_buffer *eb;
	u64 length;
	struct btrfs_multi_bio *multi = NULL;
	struct btrfs_device *device;

	eb = btrfs_find_tree_block(root, bytenr, blocksize);
	Din_Go(14526,7);if (!(eb && btrfs_buffer_uptodate(eb, parent_transid)) &&
	    !btrfs_map_block(&root->fs_info->mapping_tree, READ,
			     bytenr, &length, &multi, 0, NULL)) {
		Din_Go(14525,7);device = multi->stripes[0].dev;
		device->total_ios++;
		blocksize = min(blocksize, (u32)(64 * 1024));
		readahead(device->fd, multi->stripes[0].physical, blocksize);
	}

	Din_Go(14527,7);free_extent_buffer(eb);
	kfree(multi);
}

static int verify_parent_transid(struct extent_io_tree *io_tree,
				 struct extent_buffer *eb, u64 parent_transid,
				 int ignore)
{
	Din_Go(14528,7);int ret;

	Din_Go(14530,7);if (!parent_transid || btrfs_header_generation(eb) == parent_transid)
		{/*11*/{int  ReplaceReturn4271 = 0; Din_Go(14529,7); return ReplaceReturn4271;};/*12*/}

	Din_Go(14533,7);if (extent_buffer_uptodate(eb) &&
	    btrfs_header_generation(eb) == parent_transid) {
		Din_Go(14531,7);ret = 0;
		Din_Go(14532,7);goto out;
	}
	printk("parent transid verify failed on %llu wanted %llu found %llu\n",
	       (unsigned long long)eb->start,
	       (unsigned long long)parent_transid,
	       (unsigned long long)btrfs_header_generation(eb));
	Din_Go(14536,7);if (ignore) {
		Din_Go(14534,7);eb->flags |= EXTENT_BAD_TRANSID;
		printk("Ignoring transid failure\n");
		{int  ReplaceReturn4270 = 0; Din_Go(14535,7); return ReplaceReturn4270;};
	}

	Din_Go(14537,7);ret = 1;
out:
	clear_extent_buffer_uptodate(io_tree, eb);
	{int  ReplaceReturn4269 = ret; Din_Go(14538,7); return ReplaceReturn4269;};

}


int read_whole_eb(struct btrfs_fs_info *info, struct extent_buffer *eb, int mirror)
{
	Din_Go(14539,7);unsigned long offset = 0;
	struct btrfs_multi_bio *multi = NULL;
	struct btrfs_device *device;
	int ret = 0;
	u64 read_len;
	unsigned long bytes_left = eb->len;

	Din_Go(14556,7);while (bytes_left) {
		Din_Go(14540,7);read_len = bytes_left;
		device = NULL;

		Din_Go(14549,7);if (!info->on_restoring &&
		    eb->start != BTRFS_SUPER_INFO_OFFSET) {
			Din_Go(14541,7);ret = btrfs_map_block(&info->mapping_tree, READ,
					      eb->start + offset, &read_len, &multi,
					      mirror, NULL);
			Din_Go(14543,7);if (ret) {
				printk("Couldn't map the block %Lu\n", eb->start + offset);
				kfree(multi);
				{int  ReplaceReturn4268 = -EIO; Din_Go(14542,7); return ReplaceReturn4268;};
			}
			Din_Go(14544,7);device = multi->stripes[0].dev;

			Din_Go(14546,7);if (device->fd <= 0) {
				kfree(multi);
				{int  ReplaceReturn4267 = -EIO; Din_Go(14545,7); return ReplaceReturn4267;};
			}

			Din_Go(14547,7);eb->fd = device->fd;
			device->total_ios++;
			eb->dev_bytenr = multi->stripes[0].physical;
			kfree(multi);
			multi = NULL;
		} else {
			/* special case for restore metadump */
			list_for_each_entry(device, &info->fs_devices->devices, dev_list) {
				if (device->devid == 1)
					{/*13*/break;/*14*/}
			}

			Din_Go(14548,7);eb->fd = device->fd;
			eb->dev_bytenr = eb->start;
			device->total_ios++;
		}

		Din_Go(14551,7);if (read_len > bytes_left)
			{/*15*/Din_Go(14550,7);read_len = bytes_left;/*16*/}

		Din_Go(14552,7);ret = read_extent_from_disk(eb, offset, read_len);
		Din_Go(14554,7);if (ret)
			{/*17*/{int  ReplaceReturn4266 = -EIO; Din_Go(14553,7); return ReplaceReturn4266;};/*18*/}
		Din_Go(14555,7);offset += read_len;
		bytes_left -= read_len;
	}
	{int  ReplaceReturn4265 = 0; Din_Go(14557,7); return ReplaceReturn4265;};
}

struct extent_buffer* read_tree_block_fs_info(
		struct btrfs_fs_info *fs_info, u64 bytenr, u32 blocksize,
		u64 parent_transid)
{
	Din_Go(14558,7);int ret;
	struct extent_buffer *eb;
	u64 best_transid = 0;
	int mirror_num = 0;
	int good_mirror = 0;
	int num_copies;
	int ignore = 0;

	eb = btrfs_find_create_tree_block(fs_info, bytenr, blocksize);
	Din_Go(14560,7);if (!eb)
		{/*19*/{struct extent_buffer * ReplaceReturn4264 = ERR_PTR(-ENOMEM); Din_Go(14559,7); return ReplaceReturn4264;};/*20*/}

	Din_Go(14562,7);if (btrfs_buffer_uptodate(eb, parent_transid))
		{/*21*/{struct extent_buffer * ReplaceReturn4263 = eb; Din_Go(14561,7); return ReplaceReturn4263;};/*22*/}

	Din_Go(14587,7);while (1) {
		Din_Go(14563,7);ret = read_whole_eb(fs_info, eb, mirror_num);
		Din_Go(14568,7);if (ret == 0 && csum_tree_block_fs_info(fs_info, eb, 1) == 0 &&
		    check_tree_block(fs_info, eb) == 0 &&
		    verify_parent_transid(eb->tree, eb, parent_transid, ignore)
		    == 0) {
			Din_Go(14564,7);if (eb->flags & EXTENT_BAD_TRANSID &&
			    list_empty(&eb->recow)) {
				Din_Go(14565,7);list_add_tail(&eb->recow,
					      &fs_info->recow_ebs);
				eb->refs++;
			}
			Din_Go(14566,7);btrfs_set_buffer_uptodate(eb);
			{struct extent_buffer * ReplaceReturn4262 = eb; Din_Go(14567,7); return ReplaceReturn4262;};
		}
		Din_Go(14576,7);if (ignore) {
			Din_Go(14569,7);if (check_tree_block(fs_info, eb)) {
				Din_Go(14570,7);if (!fs_info->suppress_check_block_errors)
					{/*23*/Din_Go(14571,7);print_tree_block_error(fs_info, eb,
						check_tree_block(fs_info, eb));/*24*/}
			} else {
				Din_Go(14572,7);if (!fs_info->suppress_check_block_errors)
					{/*25*/Din_Go(14573,7);fprintf(stderr, "Csum didn't match\n");/*26*/}
			}
			Din_Go(14574,7);ret = -EIO;
			Din_Go(14575,7);break;
		}
		Din_Go(14577,7);num_copies = btrfs_num_copies(&fs_info->mapping_tree,
					      eb->start, eb->len);
		Din_Go(14580,7);if (num_copies == 1) {
			Din_Go(14578,7);ignore = 1;
			Din_Go(14579,7);continue;
		}
		Din_Go(14582,7);if (btrfs_header_generation(eb) > best_transid && mirror_num) {
			Din_Go(14581,7);best_transid = btrfs_header_generation(eb);
			good_mirror = mirror_num;
		}
		Din_Go(14583,7);mirror_num++;
		Din_Go(14586,7);if (mirror_num > num_copies) {
			Din_Go(14584,7);mirror_num = good_mirror;
			ignore = 1;
			Din_Go(14585,7);continue;
		}
	}
	Din_Go(14588,7);free_extent_buffer(eb);
	{struct extent_buffer * ReplaceReturn4261 = ERR_PTR(ret); Din_Go(14589,7); return ReplaceReturn4261;};
}

int read_extent_data(struct btrfs_root *root, char *data,
			   u64 logical, u64 *len, int mirror)
{
	Din_Go(14590,7);u64 offset = 0;
	struct btrfs_multi_bio *multi = NULL;
	struct btrfs_fs_info *info = root->fs_info;
	struct btrfs_device *device;
	int ret = 0;
	u64 max_len = *len;

	ret = btrfs_map_block(&info->mapping_tree, READ, logical, len,
			      &multi, mirror, NULL);
	Din_Go(14593,7);if (ret) {
		Din_Go(14591,7);fprintf(stderr, "Couldn't map the block %llu\n",
				logical + offset);
		Din_Go(14592,7);goto err;
	}
	Din_Go(14594,7);device = multi->stripes[0].dev;

	Din_Go(14596,7);if (device->fd <= 0)
		{/*27*/Din_Go(14595,7);goto err;/*28*/}
	Din_Go(14598,7);if (*len > max_len)
		{/*29*/Din_Go(14597,7);*len = max_len;/*30*/}

	Din_Go(14599,7);ret = pread64(device->fd, data, *len, multi->stripes[0].physical);
	Din_Go(14602,7);if (ret != *len)
		{/*31*/Din_Go(14600,7);ret = -EIO;/*32*/}
	else
		{/*33*/Din_Go(14601,7);ret = 0;/*34*/}
err:
	kfree(multi);
	{int  ReplaceReturn4260 = ret; Din_Go(14603,7); return ReplaceReturn4260;};
}

int write_and_map_eb(struct btrfs_trans_handle *trans,
		     struct btrfs_root *root,
		     struct extent_buffer *eb)
{
	Din_Go(14604,7);int ret;
	int dev_nr;
	u64 length;
	u64 *raid_map = NULL;
	struct btrfs_multi_bio *multi = NULL;

	dev_nr = 0;
	length = eb->len;
	ret = btrfs_map_block(&root->fs_info->mapping_tree, WRITE,
			      eb->start, &length, &multi, 0, &raid_map);

	Din_Go(14608,7);if (raid_map) {
		Din_Go(14605,7);ret = write_raid56_with_parity(root->fs_info, eb, multi,
					       length, raid_map);
		BUG_ON(ret);
	} else {/*35*/Din_Go(14606,7);while (dev_nr < multi->num_stripes) {
		BUG_ON(ret);
		Din_Go(14607,7);eb->fd = multi->stripes[dev_nr].dev->fd;
		eb->dev_bytenr = multi->stripes[dev_nr].physical;
		multi->stripes[dev_nr].dev->total_ios++;
		dev_nr++;
		ret = write_extent_to_disk(eb);
		BUG_ON(ret);
	/*36*/}}
	kfree(raid_map);
	kfree(multi);
	{int  ReplaceReturn4259 = 0; Din_Go(14609,7); return ReplaceReturn4259;};
}

int write_tree_block(struct btrfs_trans_handle *trans,
		     struct btrfs_root *root,
		     struct extent_buffer *eb)
{
	Din_Go(14610,7);if (check_tree_block(root->fs_info, eb)) {
		Din_Go(14611,7);print_tree_block_error(root->fs_info, eb,
				check_tree_block(root->fs_info, eb));
		BUG();
	}

	Din_Go(14612,7);if (trans && !btrfs_buffer_uptodate(eb, trans->transid))
		BUG();

	Din_Go(14613,7);btrfs_set_header_flag(eb, BTRFS_HEADER_FLAG_WRITTEN);
	csum_tree_block(root, eb, 0);

	{int  ReplaceReturn4258 = write_and_map_eb(trans, root, eb); Din_Go(14614,7); return ReplaceReturn4258;};
}

int __setup_root(u32 nodesize, u32 leafsize, u32 sectorsize,
			u32 stripesize, struct btrfs_root *root,
			struct btrfs_fs_info *fs_info, u64 objectid)
{
	Din_Go(14615,7);root->node = NULL;
	root->commit_root = NULL;
	root->sectorsize = sectorsize;
	root->nodesize = nodesize;
	root->leafsize = leafsize;
	root->stripesize = stripesize;
	root->ref_cows = 0;
	root->track_dirty = 0;

	root->fs_info = fs_info;
	root->objectid = objectid;
	root->last_trans = 0;
	root->highest_inode = 0;
	root->last_inode_alloc = 0;

	INIT_LIST_HEAD(&root->dirty_list);
	INIT_LIST_HEAD(&root->orphan_data_extents);
	memset(&root->root_key, 0, sizeof(root->root_key));
	memset(&root->root_item, 0, sizeof(root->root_item));
	root->root_key.objectid = objectid;
	{int  ReplaceReturn4257 = 0; Din_Go(14616,7); return ReplaceReturn4257;};
}

static int update_cowonly_root(struct btrfs_trans_handle *trans,
			       struct btrfs_root *root)
{
	Din_Go(14617,7);int ret;
	u64 old_root_bytenr;
	struct btrfs_root *tree_root = root->fs_info->tree_root;

	btrfs_write_dirty_block_groups(trans, root);
	Din_Go(14622,7);while(1) {
		Din_Go(14618,7);old_root_bytenr = btrfs_root_bytenr(&root->root_item);
		Din_Go(14620,7);if (old_root_bytenr == root->node->start)
			{/*37*/Din_Go(14619,7);break;/*38*/}
		Din_Go(14621,7);btrfs_set_root_bytenr(&root->root_item,
				       root->node->start);
		btrfs_set_root_generation(&root->root_item,
					  trans->transid);
		root->root_item.level = btrfs_header_level(root->node);
		ret = btrfs_update_root(trans, tree_root,
					&root->root_key,
					&root->root_item);
		BUG_ON(ret);
		btrfs_write_dirty_block_groups(trans, root);
	}
	{int  ReplaceReturn4256 = 0; Din_Go(14623,7); return ReplaceReturn4256;};
}

static int commit_tree_roots(struct btrfs_trans_handle *trans,
			     struct btrfs_fs_info *fs_info)
{
	Din_Go(14624,7);struct btrfs_root *root;
	struct list_head *next;
	struct extent_buffer *eb;
	int ret;

	Din_Go(14626,7);if (fs_info->readonly)
		{/*39*/{int  ReplaceReturn4255 = 0; Din_Go(14625,7); return ReplaceReturn4255;};/*40*/}

	Din_Go(14627,7);eb = fs_info->tree_root->node;
	extent_buffer_get(eb);
	ret = btrfs_cow_block(trans, fs_info->tree_root, eb, NULL, 0, &eb);
	free_extent_buffer(eb);
	Din_Go(14629,7);if (ret)
		{/*41*/{int  ReplaceReturn4254 = ret; Din_Go(14628,7); return ReplaceReturn4254;};/*42*/}

	Din_Go(14631,7);while(!list_empty(&fs_info->dirty_cowonly_roots)) {
		Din_Go(14630,7);next = fs_info->dirty_cowonly_roots.next;
		list_del_init(next);
		root = list_entry(next, struct btrfs_root, dirty_list);
		update_cowonly_root(trans, root);
		free_extent_buffer(root->commit_root);
		root->commit_root = NULL;
	}

	{int  ReplaceReturn4253 = 0; Din_Go(14632,7); return ReplaceReturn4253;};
}

static int __commit_transaction(struct btrfs_trans_handle *trans,
				struct btrfs_root *root)
{
	Din_Go(14633,7);u64 start;
	u64 end;
	struct extent_buffer *eb;
	struct extent_io_tree *tree = &root->fs_info->extent_cache;
	int ret;

	Din_Go(14639,7);while(1) {
		Din_Go(14634,7);ret = find_first_extent_bit(tree, 0, &start, &end,
					    EXTENT_DIRTY);
		Din_Go(14636,7);if (ret)
			{/*43*/Din_Go(14635,7);break;/*44*/}
		Din_Go(14638,7);while(start <= end) {
			Din_Go(14637,7);eb = find_first_extent_buffer(tree, start);
			BUG_ON(!eb || eb->start != start);
			ret = write_tree_block(trans, root, eb);
			BUG_ON(ret);
			start += eb->len;
			clear_extent_buffer_dirty(eb);
			free_extent_buffer(eb);
		}
	}
	{int  ReplaceReturn4252 = 0; Din_Go(14640,7); return ReplaceReturn4252;};
}

int btrfs_commit_transaction(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root)
{
	Din_Go(14641,7);u64 transid = trans->transid;
	int ret = 0;
	struct btrfs_fs_info *fs_info = root->fs_info;

	Din_Go(14643,7);if (root->commit_root == root->node)
		{/*45*/Din_Go(14642,7);goto commit_tree;/*46*/}
	Din_Go(14645,7);if (root == root->fs_info->tree_root)
		{/*47*/Din_Go(14644,7);goto commit_tree;/*48*/}
	Din_Go(14647,7);if (root == root->fs_info->chunk_root)
		{/*49*/Din_Go(14646,7);goto commit_tree;/*50*/}

	Din_Go(14648,7);free_extent_buffer(root->commit_root);
	root->commit_root = NULL;

	btrfs_set_root_bytenr(&root->root_item, root->node->start);
	btrfs_set_root_generation(&root->root_item, trans->transid);
	root->root_item.level = btrfs_header_level(root->node);
	ret = btrfs_update_root(trans, root->fs_info->tree_root,
				&root->root_key, &root->root_item);
	BUG_ON(ret);
commit_tree:
	ret = commit_tree_roots(trans, fs_info);
	BUG_ON(ret);
	ret = __commit_transaction(trans, root);
	BUG_ON(ret);
	write_ctree_super(trans, root);
	btrfs_finish_extent_commit(trans, fs_info->extent_root,
			           &fs_info->pinned_extents);
	btrfs_free_transaction(root, trans);
	free_extent_buffer(root->commit_root);
	root->commit_root = NULL;
	fs_info->running_transaction = NULL;
	fs_info->last_trans_committed = transid;
	{int  ReplaceReturn4251 = 0; Din_Go(14649,7); return ReplaceReturn4251;};
}

static int find_and_setup_root(struct btrfs_root *tree_root,
			       struct btrfs_fs_info *fs_info,
			       u64 objectid, struct btrfs_root *root)
{
	Din_Go(14650,7);int ret;
	u32 blocksize;
	u64 generation;

	__setup_root(tree_root->nodesize, tree_root->leafsize,
		     tree_root->sectorsize, tree_root->stripesize,
		     root, fs_info, objectid);
	ret = btrfs_find_last_root(tree_root, objectid,
				   &root->root_item, &root->root_key);
	Din_Go(14652,7);if (ret)
		{/*51*/{int  ReplaceReturn4250 = ret; Din_Go(14651,7); return ReplaceReturn4250;};/*52*/}

	Din_Go(14653,7);blocksize = btrfs_level_size(root, btrfs_root_level(&root->root_item));
	generation = btrfs_root_generation(&root->root_item);
	root->node = read_tree_block(root, btrfs_root_bytenr(&root->root_item),
				     blocksize, generation);
	Din_Go(14655,7);if (!extent_buffer_uptodate(root->node))
		{/*53*/{int  ReplaceReturn4249 = -EIO; Din_Go(14654,7); return ReplaceReturn4249;};/*54*/}

	{int  ReplaceReturn4248 = 0; Din_Go(14656,7); return ReplaceReturn4248;};
}

static int find_and_setup_log_root(struct btrfs_root *tree_root,
			       struct btrfs_fs_info *fs_info,
			       struct btrfs_super_block *disk_super)
{
	Din_Go(14657,7);u32 blocksize;
	u64 blocknr = btrfs_super_log_root(disk_super);
	struct btrfs_root *log_root = malloc(sizeof(struct btrfs_root));

	Din_Go(14659,7);if (!log_root)
		{/*55*/{int  ReplaceReturn4247 = -ENOMEM; Din_Go(14658,7); return ReplaceReturn4247;};/*56*/}

	Din_Go(14662,7);if (blocknr == 0) {
		Din_Go(14660,7);free(log_root);
		{int  ReplaceReturn4246 = 0; Din_Go(14661,7); return ReplaceReturn4246;};
	}

	Din_Go(14663,7);blocksize = btrfs_level_size(tree_root,
			     btrfs_super_log_root_level(disk_super));

	__setup_root(tree_root->nodesize, tree_root->leafsize,
		     tree_root->sectorsize, tree_root->stripesize,
		     log_root, fs_info, BTRFS_TREE_LOG_OBJECTID);

	log_root->node = read_tree_block(tree_root, blocknr,
				     blocksize,
				     btrfs_super_generation(disk_super) + 1);

	fs_info->log_root_tree = log_root;

	Din_Go(14666,7);if (!extent_buffer_uptodate(log_root->node)) {
		Din_Go(14664,7);free_extent_buffer(log_root->node);
		free(log_root);
		fs_info->log_root_tree = NULL;
		{int  ReplaceReturn4245 = -EIO; Din_Go(14665,7); return ReplaceReturn4245;};
	}

	{int  ReplaceReturn4244 = 0; Din_Go(14667,7); return ReplaceReturn4244;};
}

int btrfs_free_fs_root(struct btrfs_root *root)
{
	Din_Go(14668,7);if (root->node)
		{/*57*/Din_Go(14669,7);free_extent_buffer(root->node);/*58*/}
	Din_Go(14671,7);if (root->commit_root)
		{/*59*/Din_Go(14670,7);free_extent_buffer(root->commit_root);/*60*/}
	kfree(root);
	{int  ReplaceReturn4243 = 0; Din_Go(14672,7); return ReplaceReturn4243;};
}

static void __free_fs_root(struct rb_node *node)
{
	Din_Go(14673,7);struct btrfs_root *root;

	root = container_of(node, struct btrfs_root, rb_node);
	btrfs_free_fs_root(root);Din_Go(14674,7);
}

FREE_RB_BASED_TREE(fs_roots, __free_fs_root);

struct btrfs_root *btrfs_read_fs_root_no_cache(struct btrfs_fs_info *fs_info,
					       struct btrfs_key *location)
{
	Din_Go(14675,7);struct btrfs_root *root;
	struct btrfs_root *tree_root = fs_info->tree_root;
	struct btrfs_path *path;
	struct extent_buffer *l;
	u64 generation;
	u32 blocksize;
	int ret = 0;

	root = calloc(1, sizeof(*root));
	Din_Go(14677,7);if (!root)
		{/*61*/{struct btrfs_root * ReplaceReturn4242 = ERR_PTR(-ENOMEM); Din_Go(14676,7); return ReplaceReturn4242;};/*62*/}
	Din_Go(14683,7);if (location->offset == (u64)-1) {
		Din_Go(14678,7);ret = find_and_setup_root(tree_root, fs_info,
					  location->objectid, root);
		Din_Go(14681,7);if (ret) {
			Din_Go(14679,7);free(root);
			{struct btrfs_root * ReplaceReturn4241 = ERR_PTR(ret); Din_Go(14680,7); return ReplaceReturn4241;};
		}
		Din_Go(14682,7);goto insert;
	}

	Din_Go(14684,7);__setup_root(tree_root->nodesize, tree_root->leafsize,
		     tree_root->sectorsize, tree_root->stripesize,
		     root, fs_info, location->objectid);

	path = btrfs_alloc_path();
	BUG_ON(!path);
	ret = btrfs_search_slot(NULL, tree_root, location, path, 0, 0);
	Din_Go(14688,7);if (ret != 0) {
		Din_Go(14685,7);if (ret > 0)
			{/*63*/Din_Go(14686,7);ret = -ENOENT;/*64*/}
		Din_Go(14687,7);goto out;
	}
	Din_Go(14689,7);l = path->nodes[0];
	read_extent_buffer(l, &root->root_item,
	       btrfs_item_ptr_offset(l, path->slots[0]),
	       sizeof(root->root_item));
	memcpy(&root->root_key, location, sizeof(*location));
	ret = 0;
out:
	btrfs_free_path(path);
	Din_Go(14692,7);if (ret) {
		Din_Go(14690,7);free(root);
		{struct btrfs_root * ReplaceReturn4240 = ERR_PTR(ret); Din_Go(14691,7); return ReplaceReturn4240;};
	}
	Din_Go(14693,7);generation = btrfs_root_generation(&root->root_item);
	blocksize = btrfs_level_size(root, btrfs_root_level(&root->root_item));
	root->node = read_tree_block(root, btrfs_root_bytenr(&root->root_item),
				     blocksize, generation);
	Din_Go(14696,7);if (!extent_buffer_uptodate(root->node)) {
		Din_Go(14694,7);free(root);
		{struct btrfs_root * ReplaceReturn4239 = ERR_PTR(-EIO); Din_Go(14695,7); return ReplaceReturn4239;};
	}
insert:
	Din_Go(14697,7);root->ref_cows = 1;
	{struct btrfs_root * ReplaceReturn4238 = root; Din_Go(14698,7); return ReplaceReturn4238;};
}

static int btrfs_fs_roots_compare_objectids(struct rb_node *node,
					    void *data)
{
	Din_Go(14699,7);u64 objectid = *((u64 *)data);
	struct btrfs_root *root;

	root = rb_entry(node, struct btrfs_root, rb_node);
	Din_Go(14704,7);if (objectid > root->objectid)
		{/*65*/{int  ReplaceReturn4237 = 1; Din_Go(14700,7); return ReplaceReturn4237;};/*66*/}
	else {/*67*/Din_Go(14701,7);if (objectid < root->objectid)
		{/*69*/{int  ReplaceReturn4236 = -1; Din_Go(14702,7); return ReplaceReturn4236;};/*70*/}
	else
		{/*71*/{int  ReplaceReturn4235 = 0; Din_Go(14703,7); return ReplaceReturn4235;};/*72*/}/*68*/}Din_Go(14705,7);
}

static int btrfs_fs_roots_compare_roots(struct rb_node *node1,
					struct rb_node *node2)
{
	Din_Go(14706,7);struct btrfs_root *root;

	root = rb_entry(node2, struct btrfs_root, rb_node);
	{int  ReplaceReturn4234 = btrfs_fs_roots_compare_objectids(node1, (void *)&root->objectid); Din_Go(14707,7); return ReplaceReturn4234;};
}

struct btrfs_root *btrfs_read_fs_root(struct btrfs_fs_info *fs_info,
				      struct btrfs_key *location)
{
	Din_Go(14708,7);struct btrfs_root *root;
	struct rb_node *node;
	int ret;
	u64 objectid = location->objectid;

	Din_Go(14710,7);if (location->objectid == BTRFS_ROOT_TREE_OBJECTID)
		{/*73*/{struct btrfs_root * ReplaceReturn4233 = fs_info->tree_root; Din_Go(14709,7); return ReplaceReturn4233;};/*74*/}
	Din_Go(14712,7);if (location->objectid == BTRFS_EXTENT_TREE_OBJECTID)
		{/*75*/{struct btrfs_root * ReplaceReturn4232 = fs_info->extent_root; Din_Go(14711,7); return ReplaceReturn4232;};/*76*/}
	Din_Go(14714,7);if (location->objectid == BTRFS_CHUNK_TREE_OBJECTID)
		{/*77*/{struct btrfs_root * ReplaceReturn4231 = fs_info->chunk_root; Din_Go(14713,7); return ReplaceReturn4231;};/*78*/}
	Din_Go(14716,7);if (location->objectid == BTRFS_DEV_TREE_OBJECTID)
		{/*79*/{struct btrfs_root * ReplaceReturn4230 = fs_info->dev_root; Din_Go(14715,7); return ReplaceReturn4230;};/*80*/}
	Din_Go(14718,7);if (location->objectid == BTRFS_CSUM_TREE_OBJECTID)
		{/*81*/{struct btrfs_root * ReplaceReturn4229 = fs_info->csum_root; Din_Go(14717,7); return ReplaceReturn4229;};/*82*/}
	Din_Go(14720,7);if (location->objectid == BTRFS_QUOTA_TREE_OBJECTID)
		{/*83*/{struct btrfs_root * ReplaceReturn4228 = fs_info->quota_root; Din_Go(14719,7); return ReplaceReturn4228;};/*84*/}

	BUG_ON(location->objectid == BTRFS_TREE_RELOC_OBJECTID ||
	       location->offset != (u64)-1);

	Din_Go(14721,7);node = rb_search(&fs_info->fs_root_tree, (void *)&objectid,
			 btrfs_fs_roots_compare_objectids, NULL);
	Din_Go(14723,7);if (node)
		{/*85*/{struct btrfs_root * ReplaceReturn4227 = container_of(node, struct btrfs_root, rb_node); Din_Go(14722,7); return ReplaceReturn4227;};/*86*/}

	Din_Go(14724,7);root = btrfs_read_fs_root_no_cache(fs_info, location);
	Din_Go(14726,7);if (IS_ERR(root))
		{/*87*/{struct btrfs_root * ReplaceReturn4226 = root; Din_Go(14725,7); return ReplaceReturn4226;};/*88*/}

	Din_Go(14727,7);ret = rb_insert(&fs_info->fs_root_tree, &root->rb_node,
			btrfs_fs_roots_compare_roots);
	BUG_ON(ret);
	{struct btrfs_root * ReplaceReturn4225 = root; Din_Go(14728,7); return ReplaceReturn4225;};
}

void btrfs_free_fs_info(struct btrfs_fs_info *fs_info)
{
	Din_Go(14729,7);free(fs_info->tree_root);
	free(fs_info->extent_root);
	free(fs_info->chunk_root);
	free(fs_info->dev_root);
	free(fs_info->csum_root);
	free(fs_info->quota_root);
	free(fs_info->free_space_root);
	free(fs_info->super_copy);
	free(fs_info->log_root_tree);
	free(fs_info);Din_Go(14730,7);
}

struct btrfs_fs_info *btrfs_new_fs_info(int writable, u64 sb_bytenr)
{
	Din_Go(14731,7);struct btrfs_fs_info *fs_info;

	fs_info = calloc(1, sizeof(struct btrfs_fs_info));
	Din_Go(14733,7);if (!fs_info)
		{/*89*/{btrfs_fs_info * ReplaceReturn4224 = NULL; Din_Go(14732,7); return ReplaceReturn4224;};/*90*/}

	Din_Go(14734,7);fs_info->tree_root = calloc(1, sizeof(struct btrfs_root));
	fs_info->extent_root = calloc(1, sizeof(struct btrfs_root));
	fs_info->chunk_root = calloc(1, sizeof(struct btrfs_root));
	fs_info->dev_root = calloc(1, sizeof(struct btrfs_root));
	fs_info->csum_root = calloc(1, sizeof(struct btrfs_root));
	fs_info->quota_root = calloc(1, sizeof(struct btrfs_root));
	fs_info->free_space_root = calloc(1, sizeof(struct btrfs_root));
	fs_info->super_copy = calloc(1, BTRFS_SUPER_INFO_SIZE);

	Din_Go(14736,7);if (!fs_info->tree_root || !fs_info->extent_root ||
	    !fs_info->chunk_root || !fs_info->dev_root ||
	    !fs_info->csum_root || !fs_info->quota_root ||
	    !fs_info->free_space_root || !fs_info->super_copy)
		{/*91*/Din_Go(14735,7);goto free_all;/*92*/}

	Din_Go(14737,7);extent_io_tree_init(&fs_info->extent_cache);
	extent_io_tree_init(&fs_info->free_space_cache);
	extent_io_tree_init(&fs_info->block_group_cache);
	extent_io_tree_init(&fs_info->pinned_extents);
	extent_io_tree_init(&fs_info->pending_del);
	extent_io_tree_init(&fs_info->extent_ins);
	fs_info->excluded_extents = NULL;

	fs_info->fs_root_tree = RB_ROOT;
	cache_tree_init(&fs_info->mapping_tree.cache_tree);

	mutex_init(&fs_info->fs_mutex);
	INIT_LIST_HEAD(&fs_info->dirty_cowonly_roots);
	INIT_LIST_HEAD(&fs_info->space_info);
	INIT_LIST_HEAD(&fs_info->recow_ebs);

	Din_Go(14739,7);if (!writable)
		{/*93*/Din_Go(14738,7);fs_info->readonly = 1;/*94*/}

	Din_Go(14740,7);fs_info->super_bytenr = sb_bytenr;
	fs_info->data_alloc_profile = (u64)-1;
	fs_info->metadata_alloc_profile = (u64)-1;
	fs_info->system_alloc_profile = fs_info->metadata_alloc_profile;
	{btrfs_fs_info * ReplaceReturn4223 = fs_info; Din_Go(14741,7); return ReplaceReturn4223;};
free_all:
	btrfs_free_fs_info(fs_info);
	return NULL;
}

int btrfs_check_fs_compatibility(struct btrfs_super_block *sb, int writable)
{
	Din_Go(14742,7);u64 features;

	features = btrfs_super_incompat_flags(sb) &
		   ~BTRFS_FEATURE_INCOMPAT_SUPP;
	Din_Go(14744,7);if (features) {
		printk("couldn't open because of unsupported "
		       "option features (%Lx).\n",
		       (unsigned long long)features);
		{int  ReplaceReturn4222 = -ENOTSUP; Din_Go(14743,7); return ReplaceReturn4222;};
	}

	Din_Go(14745,7);features = btrfs_super_incompat_flags(sb);
	Din_Go(14747,7);if (!(features & BTRFS_FEATURE_INCOMPAT_MIXED_BACKREF)) {
		Din_Go(14746,7);features |= BTRFS_FEATURE_INCOMPAT_MIXED_BACKREF;
		btrfs_set_super_incompat_flags(sb, features);
	}

	Din_Go(14748,7);features = btrfs_super_compat_ro_flags(sb) &
		~BTRFS_FEATURE_COMPAT_RO_SUPP;
	Din_Go(14750,7);if (writable && features) {
		printk("couldn't open RDWR because of unsupported "
		       "option features (%Lx).\n",
		       (unsigned long long)features);
		{int  ReplaceReturn4221 = -ENOTSUP; Din_Go(14749,7); return ReplaceReturn4221;};
	}
	{int  ReplaceReturn4220 = 0; Din_Go(14751,7); return ReplaceReturn4220;};
}

static int find_best_backup_root(struct btrfs_super_block *super)
{
	Din_Go(14752,7);struct btrfs_root_backup *backup;
	u64 orig_gen = btrfs_super_generation(super);
	u64 gen = 0;
	int best_index = 0;
	int i;

	Din_Go(14756,7);for (i = 0; i < BTRFS_NUM_BACKUP_ROOTS; i++) {
		Din_Go(14753,7);backup = super->super_roots + i;
		Din_Go(14755,7);if (btrfs_backup_tree_root_gen(backup) != orig_gen &&
		    btrfs_backup_tree_root_gen(backup) > gen) {
			Din_Go(14754,7);best_index = i;
			gen = btrfs_backup_tree_root_gen(backup);
		}
	}
	{int  ReplaceReturn4219 = best_index; Din_Go(14757,7); return ReplaceReturn4219;};
}

static int setup_root_or_create_block(struct btrfs_fs_info *fs_info,
				      enum btrfs_open_ctree_flags flags,
				      struct btrfs_root *info_root,
				      u64 objectid, char *str)
{
	Din_Go(14758,7);struct btrfs_super_block *sb = fs_info->super_copy;
	struct btrfs_root *root = fs_info->tree_root;
	u32 leafsize = btrfs_super_leafsize(sb);
	int ret;

	ret = find_and_setup_root(root, fs_info, objectid, info_root);
	Din_Go(14765,7);if (ret) {
		printk("Couldn't setup %s tree\n", str);
		Din_Go(14760,7);if (!(flags & OPEN_CTREE_PARTIAL))
			{/*95*/{int  ReplaceReturn4218 = -EIO; Din_Go(14759,7); return ReplaceReturn4218;};/*96*/}
		/*
		 * Need a blank node here just so we don't screw up in the
		 * million of places that assume a root has a valid ->node
		 */
		Din_Go(14761,7);info_root->node =
			btrfs_find_create_tree_block(fs_info, 0, leafsize);
		Din_Go(14763,7);if (!info_root->node)
			{/*97*/{int  ReplaceReturn4217 = -ENOMEM; Din_Go(14762,7); return ReplaceReturn4217;};/*98*/}
		Din_Go(14764,7);clear_extent_buffer_uptodate(NULL, info_root->node);
	}

	{int  ReplaceReturn4216 = 0; Din_Go(14766,7); return ReplaceReturn4216;};
}

int btrfs_setup_all_roots(struct btrfs_fs_info *fs_info, u64 root_tree_bytenr,
			  enum btrfs_open_ctree_flags flags)
{
	Din_Go(14767,7);struct btrfs_super_block *sb = fs_info->super_copy;
	struct btrfs_root *root;
	struct btrfs_key key;
	u32 sectorsize;
	u32 nodesize;
	u32 leafsize;
	u32 stripesize;
	u64 generation;
	u32 blocksize;
	int ret;

	nodesize = btrfs_super_nodesize(sb);
	leafsize = btrfs_super_leafsize(sb);
	sectorsize = btrfs_super_sectorsize(sb);
	stripesize = btrfs_super_stripesize(sb);

	root = fs_info->tree_root;
	__setup_root(nodesize, leafsize, sectorsize, stripesize,
		     root, fs_info, BTRFS_ROOT_TREE_OBJECTID);
	blocksize = btrfs_level_size(root, btrfs_super_root_level(sb));
	generation = btrfs_super_generation(sb);

	Din_Go(14775,7);if (!root_tree_bytenr && !(flags & OPEN_CTREE_BACKUP_ROOT)) {
		Din_Go(14768,7);root_tree_bytenr = btrfs_super_root(sb);
	} else {/*99*/Din_Go(14769,7);if (flags & OPEN_CTREE_BACKUP_ROOT) {
		Din_Go(14770,7);struct btrfs_root_backup *backup;
		int index = find_best_backup_root(sb);
		Din_Go(14773,7);if (index >= BTRFS_NUM_BACKUP_ROOTS) {
			Din_Go(14771,7);fprintf(stderr, "Invalid backup root number\n");
			{int  ReplaceReturn4215 = -EIO; Din_Go(14772,7); return ReplaceReturn4215;};
		}
		Din_Go(14774,7);backup = fs_info->super_copy->super_roots + index;
		root_tree_bytenr = btrfs_backup_tree_root(backup);
		generation = btrfs_backup_tree_root_gen(backup);
	/*100*/}}

	Din_Go(14776,7);root->node = read_tree_block(root, root_tree_bytenr, blocksize,
				     generation);
	Din_Go(14779,7);if (!extent_buffer_uptodate(root->node)) {
		Din_Go(14777,7);fprintf(stderr, "Couldn't read tree root\n");
		{int  ReplaceReturn4214 = -EIO; Din_Go(14778,7); return ReplaceReturn4214;};
	}

	Din_Go(14780,7);ret = setup_root_or_create_block(fs_info, flags, fs_info->extent_root,
					 BTRFS_EXTENT_TREE_OBJECTID, "extent");
	Din_Go(14782,7);if (ret)
		{/*101*/{int  ReplaceReturn4213 = ret; Din_Go(14781,7); return ReplaceReturn4213;};/*102*/}
	Din_Go(14783,7);fs_info->extent_root->track_dirty = 1;

	ret = find_and_setup_root(root, fs_info, BTRFS_DEV_TREE_OBJECTID,
				  fs_info->dev_root);
	Din_Go(14785,7);if (ret) {
		printk("Couldn't setup device tree\n");
		{int  ReplaceReturn4212 = -EIO; Din_Go(14784,7); return ReplaceReturn4212;};
	}
	Din_Go(14786,7);fs_info->dev_root->track_dirty = 1;

	ret = setup_root_or_create_block(fs_info, flags, fs_info->csum_root,
					 BTRFS_CSUM_TREE_OBJECTID, "csum");
	Din_Go(14788,7);if (ret)
		{/*103*/{int  ReplaceReturn4211 = ret; Din_Go(14787,7); return ReplaceReturn4211;};/*104*/}
	Din_Go(14789,7);fs_info->csum_root->track_dirty = 1;

	ret = find_and_setup_root(root, fs_info, BTRFS_QUOTA_TREE_OBJECTID,
				  fs_info->quota_root);
	Din_Go(14791,7);if (ret == 0)
		{/*105*/Din_Go(14790,7);fs_info->quota_enabled = 1;/*106*/}

	Din_Go(14796,7);if (btrfs_fs_compat_ro(fs_info, BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE)) {
		Din_Go(14792,7);ret = find_and_setup_root(root, fs_info, BTRFS_FREE_SPACE_TREE_OBJECTID,
					  fs_info->free_space_root);
		Din_Go(14794,7);if (ret) {
			printk("Couldn't read free space tree\n");
			{int  ReplaceReturn4210 = -EIO; Din_Go(14793,7); return ReplaceReturn4210;};
		}
		Din_Go(14795,7);fs_info->free_space_root->track_dirty = 1;
	}

	Din_Go(14797,7);ret = find_and_setup_log_root(root, fs_info, sb);
	Din_Go(14800,7);if (ret) {
		printk("Couldn't setup log root tree\n");
		Din_Go(14799,7);if (!(flags & OPEN_CTREE_PARTIAL))
			{/*107*/{int  ReplaceReturn4209 = -EIO; Din_Go(14798,7); return ReplaceReturn4209;};/*108*/}
	}

	Din_Go(14801,7);fs_info->generation = generation;
	fs_info->last_trans_committed = generation;
	Din_Go(14803,7);if (extent_buffer_uptodate(fs_info->extent_root->node) &&
	    !(flags & OPEN_CTREE_NO_BLOCK_GROUPS))
		{/*109*/Din_Go(14802,7);btrfs_read_block_groups(fs_info->tree_root);/*110*/}

	Din_Go(14804,7);key.objectid = BTRFS_FS_TREE_OBJECTID;
	key.type = BTRFS_ROOT_ITEM_KEY;
	key.offset = (u64)-1;
	fs_info->fs_root = btrfs_read_fs_root(fs_info, &key);

	Din_Go(14806,7);if (IS_ERR(fs_info->fs_root))
		{/*111*/{int  ReplaceReturn4208 = -EIO; Din_Go(14805,7); return ReplaceReturn4208;};/*112*/}
	{int  ReplaceReturn4207 = 0; Din_Go(14807,7); return ReplaceReturn4207;};
}

void btrfs_release_all_roots(struct btrfs_fs_info *fs_info)
{
	Din_Go(14808,7);if (fs_info->free_space_root)
		{/*113*/Din_Go(14809,7);free_extent_buffer(fs_info->free_space_root->node);/*114*/}
	Din_Go(14811,7);if (fs_info->quota_root)
		{/*115*/Din_Go(14810,7);free_extent_buffer(fs_info->quota_root->node);/*116*/}
	Din_Go(14813,7);if (fs_info->csum_root)
		{/*117*/Din_Go(14812,7);free_extent_buffer(fs_info->csum_root->node);/*118*/}
	Din_Go(14815,7);if (fs_info->dev_root)
		{/*119*/Din_Go(14814,7);free_extent_buffer(fs_info->dev_root->node);/*120*/}
	Din_Go(14817,7);if (fs_info->extent_root)
		{/*121*/Din_Go(14816,7);free_extent_buffer(fs_info->extent_root->node);/*122*/}
	Din_Go(14819,7);if (fs_info->tree_root)
		{/*123*/Din_Go(14818,7);free_extent_buffer(fs_info->tree_root->node);/*124*/}
	Din_Go(14821,7);if (fs_info->log_root_tree)
		{/*125*/Din_Go(14820,7);free_extent_buffer(fs_info->log_root_tree->node);/*126*/}
	Din_Go(14823,7);if (fs_info->chunk_root)
		{/*127*/Din_Go(14822,7);free_extent_buffer(fs_info->chunk_root->node);/*128*/}Din_Go(14824,7);
}

static void free_map_lookup(struct cache_extent *ce)
{
	Din_Go(14825,7);struct map_lookup *map;

	map = container_of(ce, struct map_lookup, ce);
	kfree(map);
}

FREE_EXTENT_CACHE_BASED_TREE(mapping_cache, free_map_lookup);

void btrfs_cleanup_all_caches(struct btrfs_fs_info *fs_info)
{
	Din_Go(14826,7);while (!list_empty(&fs_info->recow_ebs)) {
		Din_Go(14827,7);struct extent_buffer *eb;
		eb = list_first_entry(&fs_info->recow_ebs,
				      struct extent_buffer, recow);
		list_del_init(&eb->recow);
		free_extent_buffer(eb);
	}
	Din_Go(14828,7);free_mapping_cache_tree(&fs_info->mapping_tree.cache_tree);
	extent_io_tree_cleanup(&fs_info->extent_cache);
	extent_io_tree_cleanup(&fs_info->free_space_cache);
	extent_io_tree_cleanup(&fs_info->block_group_cache);
	extent_io_tree_cleanup(&fs_info->pinned_extents);
	extent_io_tree_cleanup(&fs_info->pending_del);
	extent_io_tree_cleanup(&fs_info->extent_ins);Din_Go(14829,7);
}

int btrfs_scan_fs_devices(int fd, const char *path,
			  struct btrfs_fs_devices **fs_devices,
			  u64 sb_bytenr, int super_recover,
			  int skip_devices)
{
	Din_Go(14830,7);u64 total_devs;
	u64 dev_size;
	off_t seek_ret;
	int ret;
	Din_Go(14832,7);if (!sb_bytenr)
		{/*129*/Din_Go(14831,7);sb_bytenr = BTRFS_SUPER_INFO_OFFSET;/*130*/}

	Din_Go(14833,7);seek_ret = lseek(fd, 0, SEEK_END);
	Din_Go(14835,7);if (seek_ret < 0)
		{/*131*/{int  ReplaceReturn4206 = -errno; Din_Go(14834,7); return ReplaceReturn4206;};/*132*/}

	Din_Go(14836,7);dev_size = seek_ret;
	lseek(fd, 0, SEEK_SET);
	Din_Go(14839,7);if (sb_bytenr > dev_size) {
		Din_Go(14837,7);fprintf(stderr, "Superblock bytenr is larger than device size\n");
		{int  ReplaceReturn4205 = -EINVAL; Din_Go(14838,7); return ReplaceReturn4205;};
	}

	Din_Go(14840,7);ret = btrfs_scan_one_device(fd, path, fs_devices,
				    &total_devs, sb_bytenr, super_recover);
	Din_Go(14843,7);if (ret) {
		Din_Go(14841,7);fprintf(stderr, "No valid Btrfs found on %s\n", path);
		{int  ReplaceReturn4204 = ret; Din_Go(14842,7); return ReplaceReturn4204;};
	}

	Din_Go(14847,7);if (!skip_devices && total_devs != 1) {
		Din_Go(14844,7);ret = btrfs_scan_lblkid();
		Din_Go(14846,7);if (ret)
			{/*133*/{int  ReplaceReturn4203 = ret; Din_Go(14845,7); return ReplaceReturn4203;};/*134*/}
	}
	{int  ReplaceReturn4202 = 0; Din_Go(14848,7); return ReplaceReturn4202;};
}

int btrfs_setup_chunk_tree_and_device_map(struct btrfs_fs_info *fs_info)
{
	Din_Go(14849,7);struct btrfs_super_block *sb = fs_info->super_copy;
	u32 sectorsize;
	u32 nodesize;
	u32 leafsize;
	u32 blocksize;
	u32 stripesize;
	u64 generation;
	int ret;

	nodesize = btrfs_super_nodesize(sb);
	leafsize = btrfs_super_leafsize(sb);
	sectorsize = btrfs_super_sectorsize(sb);
	stripesize = btrfs_super_stripesize(sb);

	__setup_root(nodesize, leafsize, sectorsize, stripesize,
		     fs_info->chunk_root, fs_info, BTRFS_CHUNK_TREE_OBJECTID);

	ret = btrfs_read_sys_array(fs_info->chunk_root);
	Din_Go(14851,7);if (ret)
		{/*135*/{int  ReplaceReturn4201 = ret; Din_Go(14850,7); return ReplaceReturn4201;};/*136*/}

	Din_Go(14852,7);blocksize = btrfs_level_size(fs_info->chunk_root,
				     btrfs_super_chunk_root_level(sb));
	generation = btrfs_super_chunk_root_generation(sb);

	fs_info->chunk_root->node = read_tree_block(fs_info->chunk_root,
						    btrfs_super_chunk_root(sb),
						    blocksize, generation);
	Din_Go(14858,7);if (!extent_buffer_uptodate(fs_info->chunk_root->node)) {
		Din_Go(14853,7);if (fs_info->ignore_chunk_tree_error) {
			Din_Go(14854,7);warning("cannot read chunk root, continue anyway");
			fs_info->chunk_root = NULL;
			{int  ReplaceReturn4200 = 0; Din_Go(14855,7); return ReplaceReturn4200;};
		} else {
			Din_Go(14856,7);error("cannot read chunk root");
			{int  ReplaceReturn4199 = -EIO; Din_Go(14857,7); return ReplaceReturn4199;};
		}
	}

	Din_Go(14863,7);if (!(btrfs_super_flags(sb) & BTRFS_SUPER_FLAG_METADUMP)) {
		Din_Go(14859,7);ret = btrfs_read_chunk_tree(fs_info->chunk_root);
		Din_Go(14862,7);if (ret) {
			Din_Go(14860,7);fprintf(stderr, "Couldn't read chunk tree\n");
			{int  ReplaceReturn4198 = ret; Din_Go(14861,7); return ReplaceReturn4198;};
		}
	}
	{int  ReplaceReturn4197 = 0; Din_Go(14864,7); return ReplaceReturn4197;};
}

static struct btrfs_fs_info *__open_ctree_fd(int fp, const char *path,
					     u64 sb_bytenr,
					     u64 root_tree_bytenr,
					     enum btrfs_open_ctree_flags flags)
{
	Din_Go(14865,7);struct btrfs_fs_info *fs_info;
	struct btrfs_super_block *disk_super;
	struct btrfs_fs_devices *fs_devices = NULL;
	struct extent_buffer *eb;
	int ret;
	int oflags;

	Din_Go(14867,7);if (sb_bytenr == 0)
		{/*137*/Din_Go(14866,7);sb_bytenr = BTRFS_SUPER_INFO_OFFSET;/*138*/}

	/* try to drop all the caches */
	Din_Go(14869,7);if (posix_fadvise(fp, 0, 0, POSIX_FADV_DONTNEED))
		{/*139*/Din_Go(14868,7);fprintf(stderr, "Warning, could not drop caches\n");/*140*/}

	Din_Go(14870,7);fs_info = btrfs_new_fs_info(flags & OPEN_CTREE_WRITES, sb_bytenr);
	Din_Go(14873,7);if (!fs_info) {
		Din_Go(14871,7);fprintf(stderr, "Failed to allocate memory for fs_info\n");
		{btrfs_fs_info * ReplaceReturn4196 = NULL; Din_Go(14872,7); return ReplaceReturn4196;};
	}
	Din_Go(14875,7);if (flags & OPEN_CTREE_RESTORE)
		{/*141*/Din_Go(14874,7);fs_info->on_restoring = 1;/*142*/}
	Din_Go(14877,7);if (flags & OPEN_CTREE_SUPPRESS_CHECK_BLOCK_ERRORS)
		{/*143*/Din_Go(14876,7);fs_info->suppress_check_block_errors = 1;/*144*/}
	Din_Go(14879,7);if (flags & OPEN_CTREE_IGNORE_FSID_MISMATCH)
		{/*145*/Din_Go(14878,7);fs_info->ignore_fsid_mismatch = 1;/*146*/}
	Din_Go(14881,7);if (flags & OPEN_CTREE_IGNORE_CHUNK_TREE_ERROR)
		{/*147*/Din_Go(14880,7);fs_info->ignore_chunk_tree_error = 1;/*148*/}

	Din_Go(14882,7);ret = btrfs_scan_fs_devices(fp, path, &fs_devices, sb_bytenr,
				    (flags & OPEN_CTREE_RECOVER_SUPER),
				    (flags & OPEN_CTREE_NO_DEVICES));
	Din_Go(14884,7);if (ret)
		{/*149*/Din_Go(14883,7);goto out;/*150*/}

	Din_Go(14885,7);fs_info->fs_devices = fs_devices;
	Din_Go(14888,7);if (flags & OPEN_CTREE_WRITES)
		{/*151*/Din_Go(14886,7);oflags = O_RDWR;/*152*/}
	else
		{/*153*/Din_Go(14887,7);oflags = O_RDONLY;/*154*/}

	Din_Go(14890,7);if (flags & OPEN_CTREE_EXCLUSIVE)
		{/*155*/Din_Go(14889,7);oflags |= O_EXCL;/*156*/}

	Din_Go(14891,7);ret = btrfs_open_devices(fs_devices, oflags);
	Din_Go(14893,7);if (ret)
		{/*157*/Din_Go(14892,7);goto out;/*158*/}

	Din_Go(14894,7);disk_super = fs_info->super_copy;
	Din_Go(14897,7);if (!(flags & OPEN_CTREE_RECOVER_SUPER))
		{/*159*/Din_Go(14895,7);ret = btrfs_read_dev_super(fs_devices->latest_bdev,
					   disk_super, sb_bytenr, 1);/*160*/}
	else
		{/*161*/Din_Go(14896,7);ret = btrfs_read_dev_super(fp, disk_super, sb_bytenr, 0);/*162*/}
	Din_Go(14899,7);if (ret) {
		printk("No valid btrfs found\n");
		Din_Go(14898,7);goto out_devices;
	}

	Din_Go(14902,7);if (btrfs_super_flags(disk_super) & BTRFS_SUPER_FLAG_CHANGING_FSID &&
	    !fs_info->ignore_fsid_mismatch) {
		Din_Go(14900,7);fprintf(stderr, "ERROR: Filesystem UUID change in progress\n");
		Din_Go(14901,7);goto out_devices;
	}

	Din_Go(14903,7);memcpy(fs_info->fsid, &disk_super->fsid, BTRFS_FSID_SIZE);

	ret = btrfs_check_fs_compatibility(fs_info->super_copy,
					   flags & OPEN_CTREE_WRITES);
	Din_Go(14905,7);if (ret)
		{/*163*/Din_Go(14904,7);goto out_devices;/*164*/}

	Din_Go(14906,7);ret = btrfs_setup_chunk_tree_and_device_map(fs_info);
	Din_Go(14908,7);if (ret)
		{/*165*/Din_Go(14907,7);goto out_chunk;/*166*/}

	/* Chunk tree root is unable to read, return directly */
	Din_Go(14910,7);if (!fs_info->chunk_root)
		{/*167*/{btrfs_fs_info * ReplaceReturn4195 = fs_info; Din_Go(14909,7); return ReplaceReturn4195;};/*168*/}

	Din_Go(14911,7);eb = fs_info->chunk_root->node;
	read_extent_buffer(eb, fs_info->chunk_tree_uuid,
			   btrfs_header_chunk_tree_uuid(eb),
			   BTRFS_UUID_SIZE);

	ret = btrfs_setup_all_roots(fs_info, root_tree_bytenr, flags);
	Din_Go(14913,7);if (ret && !(flags & __OPEN_CTREE_RETURN_CHUNK_ROOT) &&
	    !fs_info->ignore_chunk_tree_error)
		{/*169*/Din_Go(14912,7);goto out_chunk;/*170*/}

	{btrfs_fs_info * ReplaceReturn4194 = fs_info; Din_Go(14914,7); return ReplaceReturn4194;};

out_chunk:
	btrfs_release_all_roots(fs_info);
	btrfs_cleanup_all_caches(fs_info);
out_devices:
	btrfs_close_devices(fs_devices);
out:
	btrfs_free_fs_info(fs_info);
	return NULL;
}

struct btrfs_fs_info *open_ctree_fs_info(const char *filename,
					 u64 sb_bytenr, u64 root_tree_bytenr,
					 enum btrfs_open_ctree_flags flags)
{
	Din_Go(14915,7);int fp;
	struct btrfs_fs_info *info;
	int oflags = O_CREAT | O_RDWR;

	Din_Go(14917,7);if (!(flags & OPEN_CTREE_WRITES))
		{/*171*/Din_Go(14916,7);oflags = O_RDONLY;/*172*/}

	Din_Go(14918,7);fp = open(filename, oflags, 0600);
	Din_Go(14921,7);if (fp < 0) {
		Din_Go(14919,7);fprintf (stderr, "Could not open %s\n", filename);
		{btrfs_fs_info * ReplaceReturn4193 = NULL; Din_Go(14920,7); return ReplaceReturn4193;};
	}
	Din_Go(14922,7);info = __open_ctree_fd(fp, filename, sb_bytenr, root_tree_bytenr,
			       flags);
	close(fp);
	{btrfs_fs_info * ReplaceReturn4192 = info; Din_Go(14923,7); return ReplaceReturn4192;};
}

struct btrfs_root *open_ctree(const char *filename, u64 sb_bytenr,
			      enum btrfs_open_ctree_flags flags)
{
	Din_Go(14924,7);struct btrfs_fs_info *info;

	/* This flags may not return fs_info with any valid root */
	BUG_ON(flags & OPEN_CTREE_IGNORE_CHUNK_TREE_ERROR);
	info = open_ctree_fs_info(filename, sb_bytenr, 0, flags);
	Din_Go(14926,7);if (!info)
		{/*173*/{struct btrfs_root * ReplaceReturn4191 = NULL; Din_Go(14925,7); return ReplaceReturn4191;};/*174*/}
	Din_Go(14928,7);if (flags & __OPEN_CTREE_RETURN_CHUNK_ROOT)
		{/*175*/{struct btrfs_root * ReplaceReturn4190 = info->chunk_root; Din_Go(14927,7); return ReplaceReturn4190;};/*176*/}
	{struct btrfs_root * ReplaceReturn4189 = info->fs_root; Din_Go(14929,7); return ReplaceReturn4189;};
}

struct btrfs_root *open_ctree_fd(int fp, const char *path, u64 sb_bytenr,
				 enum btrfs_open_ctree_flags flags)
{
	Din_Go(14930,7);struct btrfs_fs_info *info;

	/* This flags may not return fs_info with any valid root */
	BUG_ON(flags & OPEN_CTREE_IGNORE_CHUNK_TREE_ERROR);
	info = __open_ctree_fd(fp, path, sb_bytenr, 0, flags);
	Din_Go(14932,7);if (!info)
		{/*177*/{struct btrfs_root * ReplaceReturn4188 = NULL; Din_Go(14931,7); return ReplaceReturn4188;};/*178*/}
	Din_Go(14934,7);if (flags & __OPEN_CTREE_RETURN_CHUNK_ROOT)
		{/*179*/{struct btrfs_root * ReplaceReturn4187 = info->chunk_root; Din_Go(14933,7); return ReplaceReturn4187;};/*180*/}
	{struct btrfs_root * ReplaceReturn4186 = info->fs_root; Din_Go(14935,7); return ReplaceReturn4186;};
}

/*
 * Check if the super is valid:
 * - nodesize/sectorsize - minimum, maximum, alignment
 * - tree block starts   - alignment
 * - number of devices   - something sane
 * - sys array size      - maximum
 */
static int check_super(struct btrfs_super_block *sb)
{
	Din_Go(14936,7);char result[BTRFS_CSUM_SIZE];
	u32 crc;
	u16 csum_type;
	int csum_size;

	Din_Go(14939,7);if (btrfs_super_magic(sb) != BTRFS_MAGIC) {
		Din_Go(14937,7);fprintf(stderr, "ERROR: superblock magic doesn't match\n");
		{int  ReplaceReturn4185 = -EIO; Din_Go(14938,7); return ReplaceReturn4185;};
	}

	Din_Go(14940,7);csum_type = btrfs_super_csum_type(sb);
	Din_Go(14943,7);if (csum_type >= ARRAY_SIZE(btrfs_csum_sizes)) {
		Din_Go(14941,7);fprintf(stderr, "ERROR: unsupported checksum algorithm %u\n",
			csum_type);
		{int  ReplaceReturn4184 = -EIO; Din_Go(14942,7); return ReplaceReturn4184;};
	}
	Din_Go(14944,7);csum_size = btrfs_csum_sizes[csum_type];

	crc = ~(u32)0;
	crc = btrfs_csum_data(NULL, (char *)sb + BTRFS_CSUM_SIZE, crc,
			      BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE);
	btrfs_csum_final(crc, result);

	Din_Go(14947,7);if (memcmp(result, sb->csum, csum_size)) {
		Din_Go(14945,7);fprintf(stderr, "ERROR: superblock checksum mismatch\n");
		{int  ReplaceReturn4183 = -EIO; Din_Go(14946,7); return ReplaceReturn4183;};
	}
	Din_Go(14950,7);if (btrfs_super_root_level(sb) >= BTRFS_MAX_LEVEL) {
		Din_Go(14948,7);fprintf(stderr, "ERROR: tree_root level too big: %d >= %d\n",
			btrfs_super_root_level(sb), BTRFS_MAX_LEVEL);
		{int  ReplaceReturn4182 = -EIO; Din_Go(14949,7); return ReplaceReturn4182;};
	}
	Din_Go(14953,7);if (btrfs_super_chunk_root_level(sb) >= BTRFS_MAX_LEVEL) {
		Din_Go(14951,7);fprintf(stderr, "ERROR: chunk_root level too big: %d >= %d\n",
			btrfs_super_chunk_root_level(sb), BTRFS_MAX_LEVEL);
		{int  ReplaceReturn4181 = -EIO; Din_Go(14952,7); return ReplaceReturn4181;};
	}
	Din_Go(14956,7);if (btrfs_super_log_root_level(sb) >= BTRFS_MAX_LEVEL) {
		Din_Go(14954,7);fprintf(stderr, "ERROR: log_root level too big: %d >= %d\n",
			btrfs_super_log_root_level(sb), BTRFS_MAX_LEVEL);
		{int  ReplaceReturn4180 = -EIO; Din_Go(14955,7); return ReplaceReturn4180;};
	}

	Din_Go(14959,7);if (!IS_ALIGNED(btrfs_super_root(sb), 4096)) {
		Din_Go(14957,7);fprintf(stderr, "ERROR: tree_root block unaligned: %llu\n",
			btrfs_super_root(sb));
		{int  ReplaceReturn4179 = -EIO; Din_Go(14958,7); return ReplaceReturn4179;};
	}
	Din_Go(14962,7);if (!IS_ALIGNED(btrfs_super_chunk_root(sb), 4096)) {
		Din_Go(14960,7);fprintf(stderr, "ERROR: chunk_root block unaligned: %llu\n",
			btrfs_super_chunk_root(sb));
		{int  ReplaceReturn4178 = -EIO; Din_Go(14961,7); return ReplaceReturn4178;};
	}
	Din_Go(14965,7);if (!IS_ALIGNED(btrfs_super_log_root(sb), 4096)) {
		Din_Go(14963,7);fprintf(stderr, "ERROR: log_root block unaligned: %llu\n",
			btrfs_super_log_root(sb));
		{int  ReplaceReturn4177 = -EIO; Din_Go(14964,7); return ReplaceReturn4177;};
	}
	Din_Go(14968,7);if (btrfs_super_nodesize(sb) < 4096) {
		Din_Go(14966,7);fprintf(stderr, "ERROR: nodesize too small: %u < 4096\n",
			btrfs_super_nodesize(sb));
		{int  ReplaceReturn4176 = -EIO; Din_Go(14967,7); return ReplaceReturn4176;};
	}
	Din_Go(14971,7);if (!IS_ALIGNED(btrfs_super_nodesize(sb), 4096)) {
		Din_Go(14969,7);fprintf(stderr, "ERROR: nodesize unaligned: %u\n",
			btrfs_super_nodesize(sb));
		{int  ReplaceReturn4175 = -EIO; Din_Go(14970,7); return ReplaceReturn4175;};
	}
	Din_Go(14974,7);if (btrfs_super_sectorsize(sb) < 4096) {
		Din_Go(14972,7);fprintf(stderr, "ERROR: sectorsize too small: %u < 4096\n",
			btrfs_super_sectorsize(sb));
		{int  ReplaceReturn4174 = -EIO; Din_Go(14973,7); return ReplaceReturn4174;};
	}
	Din_Go(14977,7);if (!IS_ALIGNED(btrfs_super_sectorsize(sb), 4096)) {
		Din_Go(14975,7);fprintf(stderr, "ERROR: sectorsize unaligned: %u\n",
			btrfs_super_sectorsize(sb));
		{int  ReplaceReturn4173 = -EIO; Din_Go(14976,7); return ReplaceReturn4173;};
	}

	Din_Go(14980,7);if (memcmp(sb->fsid, sb->dev_item.fsid, BTRFS_UUID_SIZE) != 0) {
		Din_Go(14978,7);char fsid[BTRFS_UUID_UNPARSED_SIZE];
		char dev_fsid[BTRFS_UUID_UNPARSED_SIZE];

		uuid_unparse(sb->fsid, fsid);
		uuid_unparse(sb->dev_item.fsid, dev_fsid);
		printk(KERN_ERR
			"ERROR: dev_item UUID does not match fsid: %s != %s\n",
			dev_fsid, fsid);
		{int  ReplaceReturn4172 = -EIO; Din_Go(14979,7); return ReplaceReturn4172;};
	}

	/*
	 * Hint to catch really bogus numbers, bitflips or so
	 */
	Din_Go(14982,7);if (btrfs_super_num_devices(sb) > (1UL << 31)) {
		Din_Go(14981,7);fprintf(stderr, "WARNING: suspicious number of devices: %llu\n",
			btrfs_super_num_devices(sb));
	}

	Din_Go(14985,7);if (btrfs_super_num_devices(sb) == 0) {
		Din_Go(14983,7);fprintf(stderr, "ERROR: number of devices is 0\n");
		{int  ReplaceReturn4171 = -EIO; Din_Go(14984,7); return ReplaceReturn4171;};
	}

	/*
	 * Obvious sys_chunk_array corruptions, it must hold at least one key
	 * and one chunk
	 */
	Din_Go(14988,7);if (btrfs_super_sys_array_size(sb) > BTRFS_SYSTEM_CHUNK_ARRAY_SIZE) {
		Din_Go(14986,7);fprintf(stderr, "BTRFS: system chunk array too big %u > %u\n",
			btrfs_super_sys_array_size(sb),
			BTRFS_SYSTEM_CHUNK_ARRAY_SIZE);
		{int  ReplaceReturn4170 = -EIO; Din_Go(14987,7); return ReplaceReturn4170;};
	}
	Din_Go(14991,7);if (btrfs_super_sys_array_size(sb) < sizeof(struct btrfs_disk_key)
			+ sizeof(struct btrfs_chunk)) {
		Din_Go(14989,7);fprintf(stderr, "BTRFS: system chunk array too small %u < %lu\n",
			btrfs_super_sys_array_size(sb),
			sizeof(struct btrfs_disk_key) +
			sizeof(struct btrfs_chunk));
		{int  ReplaceReturn4169 = -EIO; Din_Go(14990,7); return ReplaceReturn4169;};
	}

	{int  ReplaceReturn4168 = 0; Din_Go(14992,7); return ReplaceReturn4168;};
}

int btrfs_read_dev_super(int fd, struct btrfs_super_block *sb, u64 sb_bytenr,
			 int super_recover)
{
	Din_Go(14993,7);u8 fsid[BTRFS_FSID_SIZE];
	int fsid_is_initialized = 0;
	char tmp[BTRFS_SUPER_INFO_SIZE];
	struct btrfs_super_block *buf = (struct btrfs_super_block *)tmp;
	int i;
	int ret;
	int max_super = super_recover ? BTRFS_SUPER_MIRROR_MAX : 1;
	u64 transid = 0;
	u64 bytenr;

	Din_Go(15003,7);if (sb_bytenr != BTRFS_SUPER_INFO_OFFSET) {
		Din_Go(14994,7);ret = pread64(fd, buf, BTRFS_SUPER_INFO_SIZE, sb_bytenr);
		Din_Go(14996,7);if (ret < BTRFS_SUPER_INFO_SIZE)
			{/*181*/{int  ReplaceReturn4167 = -1; Din_Go(14995,7); return ReplaceReturn4167;};/*182*/}

		Din_Go(14998,7);if (btrfs_super_bytenr(buf) != sb_bytenr)
			{/*183*/{int  ReplaceReturn4166 = -1; Din_Go(14997,7); return ReplaceReturn4166;};/*184*/}

		Din_Go(15000,7);if (check_super(buf))
			{/*185*/{int  ReplaceReturn4165 = -1; Din_Go(14999,7); return ReplaceReturn4165;};/*186*/}
		Din_Go(15001,7);memcpy(sb, buf, BTRFS_SUPER_INFO_SIZE);
		{int  ReplaceReturn4164 = 0; Din_Go(15002,7); return ReplaceReturn4164;};
	}

	/*
	* we would like to check all the supers, but that would make
	* a btrfs mount succeed after a mkfs from a different FS.
	* So, we need to add a special mount option to scan for
	* later supers, using BTRFS_SUPER_MIRROR_MAX instead
	*/

	Din_Go(15019,7);for (i = 0; i < max_super; i++) {
		Din_Go(15004,7);bytenr = btrfs_sb_offset(i);
		ret = pread64(fd, buf, BTRFS_SUPER_INFO_SIZE, bytenr);
		Din_Go(15006,7);if (ret < BTRFS_SUPER_INFO_SIZE)
			{/*187*/Din_Go(15005,7);break;/*188*/}

		Din_Go(15008,7);if (btrfs_super_bytenr(buf) != bytenr )
			{/*189*/Din_Go(15007,7);continue;/*190*/}
		/* if magic is NULL, the device was removed */
		Din_Go(15010,7);if (btrfs_super_magic(buf) == 0 && i == 0)
			{/*191*/Din_Go(15009,7);break;/*192*/}
		Din_Go(15012,7);if (check_super(buf))
			{/*193*/Din_Go(15011,7);continue;/*194*/}

		Din_Go(15016,7);if (!fsid_is_initialized) {
			Din_Go(15013,7);memcpy(fsid, buf->fsid, sizeof(fsid));
			fsid_is_initialized = 1;
		} else {/*195*/Din_Go(15014,7);if (memcmp(fsid, buf->fsid, sizeof(fsid))) {
			/*
			 * the superblocks (the original one and
			 * its backups) contain data of different
			 * filesystems -> the super cannot be trusted
			 */
			Din_Go(15015,7);continue;
		/*196*/}}

		Din_Go(15018,7);if (btrfs_super_generation(buf) > transid) {
			Din_Go(15017,7);memcpy(sb, buf, BTRFS_SUPER_INFO_SIZE);
			transid = btrfs_super_generation(buf);
		}
	}

	{int  ReplaceReturn4163 = transid > 0 ? 0 : -1; Din_Go(15020,7); return ReplaceReturn4163;};
}

static int write_dev_supers(struct btrfs_root *root,
			    struct btrfs_super_block *sb,
			    struct btrfs_device *device)
{
	Din_Go(15021,7);u64 bytenr;
	u32 crc;
	int i, ret;

	Din_Go(15026,7);if (root->fs_info->super_bytenr != BTRFS_SUPER_INFO_OFFSET) {
		Din_Go(15022,7);btrfs_set_super_bytenr(sb, root->fs_info->super_bytenr);
		crc = ~(u32)0;
		crc = btrfs_csum_data(NULL, (char *)sb + BTRFS_CSUM_SIZE, crc,
				      BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE);
		btrfs_csum_final(crc, (char *)&sb->csum[0]);

		/*
		 * super_copy is BTRFS_SUPER_INFO_SIZE bytes and is
		 * zero filled, we can use it directly
		 */
		ret = pwrite64(device->fd, root->fs_info->super_copy,
				BTRFS_SUPER_INFO_SIZE,
				root->fs_info->super_bytenr);
		Din_Go(15024,7);if (ret != BTRFS_SUPER_INFO_SIZE)
			{/*197*/Din_Go(15023,7);goto write_err;/*198*/}
		{int  ReplaceReturn4162 = 0; Din_Go(15025,7); return ReplaceReturn4162;};
	}

	Din_Go(15033,7);for (i = 0; i < BTRFS_SUPER_MIRROR_MAX; i++) {
		Din_Go(15027,7);bytenr = btrfs_sb_offset(i);
		Din_Go(15029,7);if (bytenr + BTRFS_SUPER_INFO_SIZE > device->total_bytes)
			{/*199*/Din_Go(15028,7);break;/*200*/}

		Din_Go(15030,7);btrfs_set_super_bytenr(sb, bytenr);

		crc = ~(u32)0;
		crc = btrfs_csum_data(NULL, (char *)sb + BTRFS_CSUM_SIZE, crc,
				      BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE);
		btrfs_csum_final(crc, (char *)&sb->csum[0]);

		/*
		 * super_copy is BTRFS_SUPER_INFO_SIZE bytes and is
		 * zero filled, we can use it directly
		 */
		ret = pwrite64(device->fd, root->fs_info->super_copy,
				BTRFS_SUPER_INFO_SIZE, bytenr);
		Din_Go(15032,7);if (ret != BTRFS_SUPER_INFO_SIZE)
			{/*201*/Din_Go(15031,7);goto write_err;/*202*/}
	}

	{int  ReplaceReturn4161 = 0; Din_Go(15034,7); return ReplaceReturn4161;};

write_err:
	if (ret > 0)
		{/*203*/fprintf(stderr, "WARNING: failed to write all sb data\n");/*204*/}
	else
		{/*205*/fprintf(stderr, "WARNING: failed to write sb: %s\n",
			strerror(errno));/*206*/}
	return ret;
}

int write_all_supers(struct btrfs_root *root)
{
	Din_Go(15035,7);struct list_head *cur;
	struct list_head *head = &root->fs_info->fs_devices->devices;
	struct btrfs_device *dev;
	struct btrfs_super_block *sb;
	struct btrfs_dev_item *dev_item;
	int ret;
	u64 flags;

	sb = root->fs_info->super_copy;
	dev_item = &sb->dev_item;
	list_for_each(cur, head) {
		dev = list_entry(cur, struct btrfs_device, dev_list);
		if (!dev->writeable)
			{/*207*/continue;/*208*/}

		btrfs_set_stack_device_generation(dev_item, 0);
		btrfs_set_stack_device_type(dev_item, dev->type);
		btrfs_set_stack_device_id(dev_item, dev->devid);
		btrfs_set_stack_device_total_bytes(dev_item, dev->total_bytes);
		btrfs_set_stack_device_bytes_used(dev_item, dev->bytes_used);
		btrfs_set_stack_device_io_align(dev_item, dev->io_align);
		btrfs_set_stack_device_io_width(dev_item, dev->io_width);
		btrfs_set_stack_device_sector_size(dev_item, dev->sector_size);
		memcpy(dev_item->uuid, dev->uuid, BTRFS_UUID_SIZE);
		memcpy(dev_item->fsid, dev->fs_devices->fsid, BTRFS_UUID_SIZE);

		flags = btrfs_super_flags(sb);
		btrfs_set_super_flags(sb, flags | BTRFS_HEADER_FLAG_WRITTEN);

		ret = write_dev_supers(root, sb, dev);
		BUG_ON(ret);
	}
	{int  ReplaceReturn4160 = 0; Din_Go(15036,7); return ReplaceReturn4160;};
}

int write_ctree_super(struct btrfs_trans_handle *trans,
		      struct btrfs_root *root)
{
	Din_Go(15037,7);int ret;
	struct btrfs_root *tree_root = root->fs_info->tree_root;
	struct btrfs_root *chunk_root = root->fs_info->chunk_root;

	Din_Go(15039,7);if (root->fs_info->readonly)
		{/*209*/{int  ReplaceReturn4159 = 0; Din_Go(15038,7); return ReplaceReturn4159;};/*210*/}

	Din_Go(15040,7);btrfs_set_super_generation(root->fs_info->super_copy,
				   trans->transid);
	btrfs_set_super_root(root->fs_info->super_copy,
			     tree_root->node->start);
	btrfs_set_super_root_level(root->fs_info->super_copy,
				   btrfs_header_level(tree_root->node));
	btrfs_set_super_chunk_root(root->fs_info->super_copy,
				   chunk_root->node->start);
	btrfs_set_super_chunk_root_level(root->fs_info->super_copy,
					 btrfs_header_level(chunk_root->node));
	btrfs_set_super_chunk_root_generation(root->fs_info->super_copy,
				btrfs_header_generation(chunk_root->node));

	ret = write_all_supers(root);
	Din_Go(15042,7);if (ret)
		{/*211*/Din_Go(15041,7);fprintf(stderr, "failed to write new super block err %d\n", ret);/*212*/}
	{int  ReplaceReturn4158 = ret; Din_Go(15043,7); return ReplaceReturn4158;};
}

int close_ctree_fs_info(struct btrfs_fs_info *fs_info)
{
	Din_Go(15044,7);int ret;
	struct btrfs_trans_handle *trans;
	struct btrfs_root *root = fs_info->tree_root;

	Din_Go(15046,7);if (fs_info->last_trans_committed !=
	    fs_info->generation) {
		BUG_ON(!root);
		Din_Go(15045,7);trans = btrfs_start_transaction(root, 1);
		btrfs_commit_transaction(trans, root);
		trans = btrfs_start_transaction(root, 1);
		ret = commit_tree_roots(trans, fs_info);
		BUG_ON(ret);
		ret = __commit_transaction(trans, root);
		BUG_ON(ret);
		write_ctree_super(trans, root);
		btrfs_free_transaction(root, trans);
	}
	Din_Go(15047,7);btrfs_free_block_groups(fs_info);

	free_fs_roots_tree(&fs_info->fs_root_tree);

	btrfs_release_all_roots(fs_info);
	btrfs_close_devices(fs_info->fs_devices);
	btrfs_cleanup_all_caches(fs_info);
	btrfs_free_fs_info(fs_info);
	{int  ReplaceReturn4157 = 0; Din_Go(15048,7); return ReplaceReturn4157;};
}

int clean_tree_block(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		     struct extent_buffer *eb)
{
	{int  ReplaceReturn4156 = clear_extent_buffer_dirty(eb); Din_Go(15049,7); return ReplaceReturn4156;};
}

int wait_on_tree_block_writeback(struct btrfs_root *root,
				 struct extent_buffer *eb)
{
	{int  ReplaceReturn4155 = 0; Din_Go(15050,7); return ReplaceReturn4155;};
}

void btrfs_mark_buffer_dirty(struct extent_buffer *eb)
{
	Din_Go(15051,7);set_extent_buffer_dirty(eb);Din_Go(15052,7);
}

int btrfs_buffer_uptodate(struct extent_buffer *buf, u64 parent_transid)
{
	Din_Go(15053,7);int ret;

	ret = extent_buffer_uptodate(buf);
	Din_Go(15055,7);if (!ret)
		{/*213*/{int  ReplaceReturn4154 = ret; Din_Go(15054,7); return ReplaceReturn4154;};/*214*/}

	Din_Go(15056,7);ret = verify_parent_transid(buf->tree, buf, parent_transid, 1);
	{int  ReplaceReturn4153 = !ret; Din_Go(15057,7); return ReplaceReturn4153;};
}

int btrfs_set_buffer_uptodate(struct extent_buffer *eb)
{
	{int  ReplaceReturn4152 = set_extent_buffer_uptodate(eb); Din_Go(15058,7); return ReplaceReturn4152;};
}
