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

#ifndef GNB_DEF_H
#define GNB_DEF_H
#include <stdint.h>

typedef unsigned long long int gnb_uint64_t;

/* 64 bits node id*/
typedef unsigned long long int gnb_uuid_t;

#ifndef ALIGN_UP_8
#define ALIGN_UP_8(x) \
	((__typeof__(x))(((uintptr_t)(x) + (uintptr_t)7) & ~(uintptr_t)7))
#endif

#ifndef ALIGN_UP
#define ALIGN_UP(x, align) \
	((__typeof__(x))(((uintptr_t)(x) + ((uintptr_t)(align) - 1)) & ~((uintptr_t)(align) - 1)))
#endif


#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                                    \
					  const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
					   (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#endif
