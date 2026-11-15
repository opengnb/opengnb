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

#include <stdlib.h>
#include <string.h>
#include "gnb_hash32.h"

typedef struct _gnb_hash32_bucket_t {
    uint32_t chain_len;
    gnb_kv32_t *kv_chain;
} gnb_hash32_bucket_t;

uint32_t murmurhash_hash(unsigned char *data, size_t len);

gnb_hash32_map_t *gnb_hash32_create(gnb_heap_t *heap, uint32_t bucket_num) {
    gnb_hash32_map_t *hash32_map = (gnb_hash32_map_t *)gnb_heap_alloc(heap, sizeof(gnb_hash32_map_t));
    memset(hash32_map, 0, sizeof(gnb_hash32_map_t));
    hash32_map->heap = heap;
    hash32_map->buckets = (gnb_hash32_bucket_t **)gnb_heap_alloc(hash32_map->heap, sizeof(gnb_hash32_bucket_t *) * bucket_num);
    hash32_map->bucket_num = bucket_num;
    uint32_t i;
    void *p = gnb_heap_alloc(hash32_map->heap, sizeof(gnb_hash32_bucket_t)*bucket_num);
    memset(p, 0, sizeof(gnb_hash32_bucket_t)*bucket_num);
    for ( i=0; i<bucket_num; i++ ) {
        hash32_map->buckets[i] = p;
        p += sizeof(gnb_hash32_bucket_t);
    }
    return hash32_map;
}

void gnb_hash32_release(gnb_hash32_map_t *hash32_map) {
    if ( NULL != hash32_map->buckets ) {
        uint32_t i;
        for ( i=0; i<hash32_map->bucket_num; i++ ) {
            gnb_hash32_bucket_t *bucket = hash32_map->buckets[i];
            if ( NULL == bucket ) {
                continue;
            }
            gnb_kv32_t *kv = bucket->kv_chain;
            while ( NULL != kv ) {
                gnb_kv32_t *next = kv->nex;
                gnb_heap_free(hash32_map->heap, kv);
                kv = next;
            }
        }
        gnb_heap_free(hash32_map->heap, hash32_map->buckets[0]);
        gnb_heap_free(hash32_map->heap, hash32_map->buckets);
    }
    gnb_heap_free(hash32_map->heap, hash32_map);
}

gnb_kv32_t *gnb_kv32_create(gnb_hash32_map_t *hash32_map, u_char *key, uint32_t key_len, u_char *value, uint32_t value_len) {
    uint32_t r_value_len;
    if ( 0 != value_len ) {
        r_value_len = value_len;
    } else {
        r_value_len = sizeof(void *);
    }
    gnb_kv32_t *kv = (gnb_kv32_t *)gnb_heap_alloc(hash32_map->heap, sizeof(gnb_kv32_t) + sizeof(gnb_block32_t) + key_len + sizeof(gnb_block32_t) + r_value_len);
    if ( NULL == kv ) {
        return NULL;
    }
    void *p = (void *)kv;
    kv->key   = p + sizeof(gnb_kv32_t);
    kv->value = p + sizeof(gnb_kv32_t) + sizeof(gnb_block32_t) + key_len;
    kv->nex = NULL;
    memcpy(kv->key->data, key, key_len);
    kv->key->size = key_len;
    if ( 0 != value_len ) {
        memcpy(kv->value->data, value, value_len);
        kv->value->size = value_len;
    } else {
        //直接存 void*
        GNB_BLOCK_VOID(kv->value, value);
        kv->value->size = 0;
    }
    return kv;
}

void gnb_kv32_release(gnb_hash32_map_t *hash32_map, gnb_kv32_t *kv) {
    gnb_heap_free(hash32_map->heap, kv);
}

gnb_kv32_t *gnb_hash32_set(gnb_hash32_map_t *hash32_map, u_char *key, uint32_t key_len, void *value, uint32_t value_len) {
    gnb_kv32_t *kv = NULL;
    uint32_t hashcode = murmurhash_hash(key, key_len);
    uint32_t bucket_idx = hashcode % hash32_map->bucket_num;
    gnb_hash32_bucket_t *bucket = hash32_map->buckets[bucket_idx];
    if ( NULL == bucket->kv_chain ) {
        bucket->kv_chain = gnb_kv32_create(hash32_map, key, key_len, value, value_len);
        bucket->kv_chain->nex = NULL;
        bucket->chain_len = 1;
        hash32_map->kv_num++;
        goto finish;
    }
    gnb_kv32_t *kv_chain = bucket->kv_chain;
    gnb_kv32_t *pre_kv_chain = kv_chain;
    do {
        if ( key_len != kv_chain->key->size ) {
            pre_kv_chain = kv_chain;
            kv_chain = kv_chain->nex;
            continue;
        }
        if ( !memcmp(kv_chain->key->data, key, key_len) ) {
            kv = kv_chain;
            if ( 0 != value_len ) {
                 memcpy(kv->value->data, value, value_len);
                 kv->value->size = value_len;
            } else {
                //直接存 void*
                GNB_BLOCK_VOID(kv->value, value);
                kv->value->size = 0;
            }
            break;
        }
        pre_kv_chain = kv_chain;
        kv_chain = kv_chain->nex;
    } while (kv_chain);
    if ( NULL == kv ) {
        pre_kv_chain->nex = gnb_kv32_create(hash32_map, key, key_len, value, value_len);
        bucket->chain_len++;
        hash32_map->kv_num++;
        goto finish;
    }

finish:
    return kv;
}

int gnb_hash32_store(gnb_hash32_map_t *hash32_map, u_char *key, uint32_t key_len, void *value, uint32_t value_len) {
    gnb_kv32_t *kv = NULL;
    uint32_t hashcode = murmurhash_hash(key, key_len);
    uint32_t bucket_idx = hashcode % hash32_map->bucket_num;
    gnb_hash32_bucket_t *bucket = hash32_map->buckets[bucket_idx];
    if ( NULL == bucket->kv_chain ) {
        bucket->kv_chain = gnb_kv32_create(hash32_map, key, key_len, value, value_len);
        bucket->chain_len = 1;
        hash32_map->kv_num++;
        goto finish;
    }
    gnb_kv32_t *kv_chain = bucket->kv_chain;
    gnb_kv32_t *pre_kv_chain = kv_chain;
    do {
        if ( key_len != kv_chain->key->size ) {
            //key长度不一致,key不一致,跳过
            pre_kv_chain = kv_chain;
            kv_chain = kv_chain->nex;
            continue;
        }
        if ( memcmp(kv_chain->key->data, key, key_len) ) {
            //这里 输入的 key_len 与 kv_chain->key->size 一致,但key不一致,跳过
            pre_kv_chain = kv_chain;
            kv_chain = kv_chain->nex;
            continue;
        }
        //到这里 key 与 kv_chain 里的 key 一致
        if ( value_len == kv_chain->value->size ) {
            //如果碰巧存入的 value 与 kv_chain->value 长度一致
            //那么直接覆盖 kv_chain->value->data 就可以了
            if ( 0 != value_len ) {
                memcpy(kv_chain->value->data, value, value_len);
            } else {
                GNB_BLOCK_VOID(kv_chain->value, value);
            }
            //存下当前的 kv ,标记为找到 key 对应的value
            kv = kv_chain;
            break;
        } else {
            //虽然 key 相同,但与原 value 存储的长度不一致
            //先重新创建一个 kv,然后释放原来的 kv,
            kv = gnb_kv32_create(hash32_map, key, key_len, value, value_len);
            if ( NULL == kv ) {
                return -1;
            }
            kv->nex = kv_chain->nex;
            if ( bucket->kv_chain != kv_chain ) {
                //当 kv_chain 不是 bucket 的第一个kv
                pre_kv_chain->nex = kv;
            } else {
                bucket->kv_chain = kv;
            }
            gnb_kv32_release(hash32_map, kv_chain);
            break;
        }
    } while (kv_chain);
    //到这里,没有在 bucket 的 kv_chain 里找到对应输入的 key,那么创建一个kv,放在 kv_chain 的尾部
    if ( NULL == kv ) {
        pre_kv_chain->nex = gnb_kv32_create(hash32_map, key, key_len, value, value_len);
        bucket->chain_len++;
        hash32_map->kv_num++;
        goto finish;
    }

finish:
    return 0;
}

gnb_kv32_t *gnb_hash32_get(gnb_hash32_map_t *hash32_map, u_char *key, uint32_t key_len) {
    gnb_kv32_t *kv = NULL;
    uint32_t hashcode = murmurhash_hash(key, key_len);
    uint32_t bucket_idx = hashcode % hash32_map->bucket_num;
    gnb_hash32_bucket_t *bucket = hash32_map->buckets[bucket_idx];
    if ( NULL == bucket->kv_chain ) {
        goto finish;
    }
    gnb_kv32_t *kv_chain = bucket->kv_chain;
    do {
        if ( key_len != kv_chain->key->size ) {
            kv_chain = kv_chain->nex;
            continue;
        }
        if ( !memcmp(kv_chain->key->data, key, key_len) ) {
            kv = kv_chain;
            break;
        }
        kv_chain = kv_chain->nex;
        
    } while (kv_chain);

finish:
    return kv;
}

gnb_kv32_t *gnb_hash32_del(gnb_hash32_map_t *hash32_map, u_char *key, uint32_t key_len) {
    gnb_kv32_t *old_kv = NULL;
    uint32_t hashcode = murmurhash_hash(key, key_len);
    uint32_t bucket_idx = hashcode % hash32_map->bucket_num;
    gnb_hash32_bucket_t *bucket = hash32_map->buckets[bucket_idx];
    if ( NULL == bucket->kv_chain ) {
        goto finish;
    }
    gnb_kv32_t *kv_chain = bucket->kv_chain;
    if ( (kv_chain->key->size == key_len) && !memcmp(kv_chain->key->data, key, key_len) ) {
        old_kv = kv_chain;
        hash32_map->kv_num--;
        if ( 1 == bucket->chain_len ) {
            bucket->kv_chain = NULL;
            bucket->chain_len = 0;
        } else {
            bucket->kv_chain = kv_chain->nex;
            bucket->chain_len--;
        }
        goto finish;
    }
    gnb_kv32_t *pre_kv_chain = kv_chain;
    kv_chain = kv_chain->nex;
    if ( NULL == kv_chain ) {
        goto finish;
    }
    do {
        if ( key_len != kv_chain->key->size ) {
            pre_kv_chain = kv_chain;
            kv_chain = kv_chain->nex;
            continue;
        }
        if ( !memcmp(kv_chain->key->data, key, key_len) ) {
            pre_kv_chain->nex = kv_chain->nex;
            old_kv = kv_chain;
            bucket->chain_len--;
            hash32_map->kv_num--;
            break;
        }
        pre_kv_chain = kv_chain;
        kv_chain = kv_chain->nex;
        
    } while (kv_chain);

finish:
    return old_kv;
}
