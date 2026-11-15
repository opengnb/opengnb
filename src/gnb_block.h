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

#ifndef GNB_BLOCK_H
#define GNB_BLOCK_H

#include <stdint.h>
#include <string.h>

typedef struct _gnb_block32_t {
    uint32_t size;
    unsigned char data[0];
} gnb_block32_t;

typedef struct _gnb_block64_t {
	uint64_t size;
	unsigned char data[0];
} gnb_block64_t;

/* 把 value 以 void* 形式写入 block->data。
   原为 *(void**)&block->data,在未对齐的 data 上做 void* 解引用属 UB(非 x86 平台靠 OS/CPU 补救才未崩)。
   改为 memcpy:对任意地址合法,对齐时编译器优化成单条 store,不影响性能。
*/
#define GNB_BLOCK_VOID(block, value)  do { void *_v = (void *)(value); memcpy((block)->data, &_v, sizeof(void*)); } while (0)

#endif
