/*
   Copyright (C) gnbdev

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>      /* PRIu64:uint64_t 的跨平台打印 */

#include "gnb_def.h"
#include "gnb_ctl_block.h"
#include "gnb_mmap.h"
#include "gnb_time.h"
#include "gnb_block.h"

ssize_t gnb_ctl_file_size(const char *filename) {
    struct stat s;
    int ret;
    ret = stat(filename,&s);
    if ( 0 != ret ) {
        return -1;
    }
    return s.st_size;
}

/*
┌──────────────┬────────────────────────┐
│              │16bytes file_magic_number│
│entry_table256├────────────────────────┤
│              │     block2_offset      │
│ 64bit * 256  │────────────────────────┤
│              │     block3_offset      │
│              │────────────────────────┤
│              │     block4_offset      │
│              │────────────────────────┤
│              │     block5_offset      │
│              │────────────────────────┤
│              │     block6_offset      │
│              │────────────────────────┤
│              │      ... ... ...       │
│              │────────────────────────┤
│              │     block255_offset    │
├──────────────┼────────────────────────┤
│              │       block size       │
│    block2    ├────────────────────────┤
│              │     magic_number       │
├──────────────┼────────────────────────┤
│              │       block size       │
│    block3    ├────────────────────────┤
│              │       conf_zone        │
├──────────────┼────────────────────────┤
│              │       block size       │
│    block4    ├────────────────────────┤
│              │       core_zone        │
├──────────────┼────────────────────────┤
│              │       block size       │
│    block5    ├────────────────────────┤
│              │      status_zone       │
├──────────────┼────────────────────────┤
│              │       block size       │
│    block6    ├────────────────────────┤
│              │       node_zone        │
└──────────────┴────────────────────────┘
*/
uint64_t gnb_ctl_block_size(uint32_t payload_block_size, gnb_uint64_t node_num, uint8_t pf_worker_num) {
	uint64_t offset;
	/* core zone 尾部紧跟 (1 + pf_worker_num) 组 payload 块.
	(1 + conf->pf_worker_num) 是为  gnb_ctl_core_zone_t 中的 pf_worker_payload_blocks 预留 share memory 空间中 (primary_worker + pf_worker) 个 memmory block
	primary_worker 所使用的是 pf_worker_payload_blocks 第1块,后面的块由 pf_worker 依次占用
	sizeof(gnb_block64_t) * 5 是 share memory 中ctl_block 有5个 zone 的 gnb_block64_t 结构占用的空间
	*/
	uint64_t core_payload = (uint64_t)(
		(sizeof(gnb_payload16_t) + payload_block_size +
		 sizeof(gnb_payload16_t) + payload_block_size) * (1u + pf_worker_num) );

	/* entry_table256: 最前面 256 个 uint64_t */
	offset = (uint64_t)GNB_CTL_ENTRY_TABLE_SIZE;

	/* 1) magic number zone: 块头 8 对齐 -> data = 头+8 也 8 对齐 */
	offset = ALIGN_UP_8(offset);
	offset = offset + sizeof(gnb_block64_t);
	offset = offset + sizeof(gnb_ctl_magic_number_t);

	/* 2) conf zone */
	offset = ALIGN_UP_8(offset);
	offset = offset + sizeof(gnb_block64_t);
	offset = offset + sizeof(gnb_ctl_conf_zone_t);

	/* 3) core zone (含尾部 payload 块) */
	offset = ALIGN_UP_8(offset);
	offset = offset + sizeof(gnb_block64_t);
	offset = offset + sizeof(gnb_ctl_core_zone_t) + core_payload;

	/* 4) status zone */
	offset = ALIGN_UP_8(offset);
	offset = offset + sizeof(gnb_block64_t);
	offset = offset + sizeof(gnb_ctl_status_zone_t);

	/* 5) node zone (含尾部 node_num 个 gnb_node_t)
	   注意先转 uint64_t 再相乘,避免 32 位系统上 size_t 乘法溢出 */
	offset = ALIGN_UP_8(offset);
	offset = offset + sizeof(gnb_block64_t);
	offset = offset + sizeof(gnb_ctl_node_zone_t) + (uint64_t)sizeof(gnb_node_t) * (uint64_t)node_num;

	return offset;   /* 精确总大小, 无任何余量 */
}

gnb_ctl_block_t *gnb_ctl_block_init(gnb_ctl_block_t *ctl_block, void *memory, uint32_t payload_block_size, gnb_uint64_t node_num, uint8_t pf_worker_num) {

	uint64_t offset;

	uint64_t core_payload = (uint64_t)(
		(sizeof(gnb_payload16_t) + payload_block_size +
		 sizeof(gnb_payload16_t) + payload_block_size) * (1u + pf_worker_num) );

	gnb_block64_t *block;

	ctl_block->entry_table256 = memory;
	memset(ctl_block->entry_table256, 0, GNB_CTL_ENTRY_TABLE_SIZE);

	offset = (uint64_t)GNB_CTL_ENTRY_TABLE_SIZE;

	/* 1) magic number zone */
	offset = ALIGN_UP_8(offset);                                  /* 块头 8 对齐 */
	ctl_block->entry_table256[GNB_CTL_MAGIC_NUMBER] = offset;     /* 直接记录头偏移 */
	block = (gnb_block64_t *)((char *)memory + offset);
	block->size = sizeof(gnb_ctl_magic_number_t);
	ctl_block->magic_number = (gnb_ctl_magic_number_t *)block->data;   /* = 头+8, 8 对齐 */
	snprintf((char *)ctl_block->magic_number->data, 16, "%s", "GNB MAP File");
	offset = offset + sizeof(gnb_block64_t);
	offset = offset + sizeof(gnb_ctl_magic_number_t);

	/* 2) conf zone */
	offset = ALIGN_UP_8(offset);
	ctl_block->entry_table256[GNB_CTL_CONF] = offset;
	block = (gnb_block64_t *)((char *)memory + offset);
	block->size = sizeof(gnb_ctl_conf_zone_t);
	ctl_block->conf_zone = (gnb_ctl_conf_zone_t *)block->data;
	snprintf((char *)ctl_block->conf_zone->name, 8, "%s", "CONF");
	offset = offset + sizeof(gnb_block64_t);
	offset = offset + sizeof(gnb_ctl_conf_zone_t);

	/* 3) core zone */
	offset = ALIGN_UP_8(offset);
	ctl_block->entry_table256[GNB_CTL_CORE] = offset;
	block = (gnb_block64_t *)((char *)memory + offset);
	block->size = sizeof(gnb_ctl_core_zone_t) + core_payload;
	ctl_block->core_zone = (gnb_ctl_core_zone_t *)block->data;
	offset = offset + sizeof(gnb_block64_t);
	offset = offset + sizeof(gnb_ctl_core_zone_t) + core_payload;

	/* 4) status zone */
	offset = ALIGN_UP_8(offset);
	ctl_block->entry_table256[GNB_CTL_STATUS] = offset;
	block = (gnb_block64_t *)((char *)memory + offset);
	block->size = sizeof(gnb_ctl_status_zone_t);
	ctl_block->status_zone = (gnb_ctl_status_zone_t *)block->data;
	offset = offset + sizeof(gnb_block64_t);
	offset = offset + sizeof(gnb_ctl_status_zone_t);

	/* 5) node zone */
	offset = ALIGN_UP_8(offset);
	ctl_block->entry_table256[GNB_CTL_NODE] = offset;
	block = (gnb_block64_t *)((char *)memory + offset);
	block->size = sizeof(gnb_ctl_node_zone_t) + sizeof(gnb_node_t) * node_num;
	ctl_block->node_zone = (gnb_ctl_node_zone_t *)block->data;
	snprintf((char *)ctl_block->node_zone->name, 8, "%s", "NODE");
	ctl_block->node_zone->node_num = node_num;
	offset = offset + sizeof(gnb_block64_t);
	offset = offset + sizeof(gnb_ctl_node_zone_t)
		   + (uint64_t)sizeof(gnb_node_t) * (uint64_t)node_num;

	/* 与 gnb_ctl_block_size() 必须逐字节一致; 不一致说明两处布局漂移, 立即暴露而非静默越界 */
	if ( offset != gnb_ctl_block_size(payload_block_size, node_num, pf_worker_num) ) {
		fprintf(stderr, "gnb_ctl_block: layout mismatch (offset=%" PRIu64 ")\n", offset);
		abort();
	}

	return ctl_block;
}

void gnb_ctl_block_build_finish(void *memory) {
    gnb_ctl_block_t ctl_block_st;
    gnb_ctl_block_setup(&ctl_block_st, memory);
    ctl_block_st.status_zone->keep_alive_ts_sec = gnb_timestamp_sec();
    //写入 GNB 确定共享内存初始化完成
    char *mem_magic_number = memory;
    mem_magic_number[0] = 'G';
    mem_magic_number[1] = 'N';
    mem_magic_number[2] = 'B';
}

void gnb_ctl_block_setup(gnb_ctl_block_t *ctl_block, void *memory) {
    gnb_block64_t *block;
    ctl_block->entry_table256 = memory;
    block = (gnb_block64_t *)(memory + ctl_block->entry_table256[GNB_CTL_MAGIC_NUMBER]);
    ctl_block->magic_number = (gnb_ctl_magic_number_t *)block->data;
    block = memory + ctl_block->entry_table256[GNB_CTL_CONF];
    ctl_block->conf_zone = (gnb_ctl_conf_zone_t *)block->data;
    block = (gnb_block64_t *)(memory + ctl_block->entry_table256[GNB_CTL_CORE]);
    ctl_block->core_zone = (gnb_ctl_core_zone_t *)block->data;
    block = (gnb_block64_t *)(memory + ctl_block->entry_table256[GNB_CTL_STATUS]);
    ctl_block->status_zone = (gnb_ctl_status_zone_t *)block->data;
    block = (gnb_block64_t *)(memory + ctl_block->entry_table256[GNB_CTL_NODE]);
    ctl_block->node_zone = (gnb_ctl_node_zone_t *)block->data;
}

/*
 flag = 0 readonly
*/
// ctl_block->mmap_block 要在调用前创建好
int gnb_get_ctl_block(gnb_ctl_block_t *ctl_block, const char *ctl_block_file, int flag) {
    ssize_t ctl_file_size = 0;
    uint64_t now_sec;
    int r;
    void *memory;
    char *mem_magic_number;
    ctl_file_size = gnb_ctl_file_size(ctl_block_file);
    if ( ctl_file_size < (ssize_t)MIN_CTL_BLOCK_FILE_SIZE ) {
        return -1;
    }
    r = gnb_mmap(ctl_block->mmap_block, ctl_block_file, ctl_file_size, GNB_MMAP_TYPE_READWRITE);
    if ( 0 != r ) {
        return -1;
    }
    memory = gnb_mmap_get_block(ctl_block->mmap_block);
    mem_magic_number = (char *)memory;
    if ( 'G' != mem_magic_number[0] || 'N' != mem_magic_number[1] || 'B' != mem_magic_number[2] ) {
        return -1;
    }
    now_sec = gnb_timestamp_sec();
    gnb_ctl_block_setup(ctl_block, memory);
    if ( 0 == flag ) {
        //flag:0 readonly
        return 0;
    }
    if ( now_sec < ctl_block->status_zone->keep_alive_ts_sec ) {
        goto finish_error;
    }
    if ( now_sec == ctl_block->status_zone->keep_alive_ts_sec ) {
        return 0;
    }
    if ( (now_sec - ctl_block->status_zone->keep_alive_ts_sec) < GNB_CTL_KEEP_ALIVE_TS ) {
        return 0;
    }

finish_error:
    gnb_munmap(ctl_block->mmap_block);
    return -1;
}
