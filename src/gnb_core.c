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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#ifdef __UNIX_LIKE_OS__
#include <limits.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#endif
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "gnb.h"
#include "gnb_conf_file.h"
#include "gnb_config_lite.h"
#include "gnb_tun_drv.h"
#include "gnb_udp.h"
#include "gnb_binary.h"
#include "gnb_payload16.h"
#include "gnb_time.h"
#include "gnb_keys.h"
#include "gnb_mmap.h"
#include "gnb_time.h"

#ifdef __UNIX_LIKE_OS__
void bind_socket_if(gnb_core_t *gnb_core);
#endif

void gnb_set_env(const char *name, const char *value);
void log_out_description(gnb_log_ctx_t *log);
void setup_log_ctx(gnb_conf_t *conf, gnb_log_ctx_t *log);

static void gnb_setup_env(gnb_core_t *gnb_core) {
    char env_value_string[64];
    char address_string1[GNB_IP6_PORT_STRING_SIZE];
    gnb_set_env("GNB_IF_NAME", gnb_core->ifname);
    snprintf(env_value_string, 64, "%d", gnb_core->conf->mtu);
    gnb_set_env("GNB_MTU", env_value_string);
    gnb_set_env("GNB_TUN_IPV6", gnb_in6_addr_str(&gnb_core->local_node->tun_ipv6_addr,address_string1,gnb_core->conf->addr_secure));
    gnb_set_env("GNB_TUN_IPV4", gnb_in6_addr_str(&gnb_core->local_node->tun_addr4,address_string1,gnb_core->conf->addr_secure));
}

static void ctl_block_create(gnb_core_t *gnb_core, gnb_conf_t *conf) {
    gnb_mmap_block_t *mmap_block;
    void *memory;
    int r;
	gnb_uint64_t node_num = 0;
	gnb_uint64_t ctl_block_size;
    if ( 0 == conf->public_index_service && 0 == conf->lite_mode ) {
        //大致算出 node 的数量
        node_num = gnb_get_node_num_from_file(conf);
        if ( 0==node_num ) {
            node_num = 256;
        }
    } else if ( 1 == conf->public_index_service && 0 == conf->lite_mode ) {
        node_num = 0;
    } else if ( 0 == conf->public_index_service && 1 == conf->lite_mode ) {
        node_num = 256;
    } else {
        node_num = 256;
    }

	ctl_block_size = gnb_ctl_block_size(conf->payload_block_size, node_num, conf->pf_worker_num);
	if ( ctl_block_size > (uint64_t)SIZE_MAX ) {
			printf("init_ctl_block error: ctl_block size %llu exceeds SIZE_MAX\n", ctl_block_size);
			exit(1);
	}

    unlink(conf->map_file);
    mmap_block = gnb_heap_alloc(gnb_core->heap, sizeof(gnb_mmap_block_t));
    r = gnb_mmap(mmap_block, conf->map_file, ctl_block_size, GNB_MMAP_TYPE_READWRITE|GNB_MMAP_TYPE_CREATE);
    if ( 0 != r ) {
        printf("init_ctl_block error[%p] map_file=%s\n",mmap_block, conf->map_file);
        exit(1);
    }
    memory = gnb_mmap_get_block(mmap_block);
    gnb_core->ctl_block = gnb_heap_alloc(gnb_core->heap, sizeof(gnb_ctl_block_t));
    gnb_ctl_block_init(gnb_core->ctl_block, memory, conf->payload_block_size, node_num, conf->pf_worker_num);
    gnb_core->ctl_block->mmap_block = mmap_block;
}

static void ctl_block_release(gnb_core_t *gnb_core) {
    gnb_munmap(gnb_core->ctl_block->mmap_block);
    gnb_heap_free(gnb_core->heap, gnb_core->ctl_block->mmap_block);
    gnb_heap_free(gnb_core->heap, gnb_core->ctl_block);
}

void update_node_crypto_key(gnb_core_t *gnb_core, uint64_t now_sec) {
    int need_update_time_seed;
	gnb_uint64_t num = gnb_core->ctl_block->node_zone->node_num;
    if ( 0 == num ) {
        return;
    }
    need_update_time_seed = gnb_verify_seed_time(gnb_core, now_sec);
    if ( 0 == need_update_time_seed ) {
        return;
    }
    gnb_update_time_seed(gnb_core, now_sec);
    int i;
    gnb_node_t *node;
    for ( i=0; i<num; i++ ) {
        node = &gnb_core->ctl_block->node_zone->node[i];
        if ( gnb_core->local_node->uuid64 == node->uuid64 ) {
            continue;
        }
        gnb_build_crypto_key(gnb_core, node);
    }
}

gnb_core_t* gnb_core_create(gnb_conf_t *conf) {
    gnb_core_t *gnb_core;
    gnb_heap_t *heap = gnb_heap_create(conf->max_heap_fragment);
    gnb_core = gnb_heap_alloc(heap, sizeof(gnb_core_t));
    memset(gnb_core, 0, sizeof(gnb_core_t));
    gnb_core->heap = heap;
    gnb_core->heap_lru32 = gnb_heap_create(conf->index_service_lru_size + 128);
    ctl_block_create(gnb_core, conf);
    gnb_core->conf = &gnb_core->ctl_block->conf_zone->conf_st;
    memcpy(gnb_core->conf, conf, sizeof(gnb_conf_t));
    gnb_core->log = &gnb_core->ctl_block->core_zone->log_ctx_st;
    gnb_log_ctx_init(gnb_core->log);
    gnb_core->ed25519_private_key = gnb_core->ctl_block->core_zone->ed25519_private_key;
    gnb_core->ed25519_public_key  = gnb_core->ctl_block->core_zone->ed25519_public_key;
    gnb_core->index_address_ring.address_list = (gnb_address_list_t *)gnb_core->ctl_block->core_zone->index_address_block;
    gnb_core->index_address_ring.address_list->num  = 0;
    gnb_core->index_address_ring.address_list->size = GNB_MAX_ADDR_RING;
    gnb_core->fwdu0_address_ring.address_list = (gnb_address_list_t *)gnb_core->ctl_block->core_zone->ufwd_address_block;
    gnb_core->fwdu0_address_ring.address_list->num = 0;
    gnb_core->fwdu0_address_ring.address_list->size = 16;
    gnb_core->ifname = (char *)gnb_core->ctl_block->core_zone->ifname;
    gnb_core->if_device_string = (char *)gnb_core->ctl_block->core_zone->if_device_string;
    gnb_core->uuid_node_map   = gnb_hash32_create(gnb_core->heap, 1024); //以节点的uuid64作为key的 node 表
    gnb_core->ipv4_node_map   = gnb_hash32_create(gnb_core->heap, 1024);

    //以节点的subnet(uint32)作为key的 node ring 表
    gnb_core->subneta_node_ring_map = gnb_hash32_create(gnb_core->heap, 1024);
    gnb_core->subnetb_node_ring_map = gnb_hash32_create(gnb_core->heap, 1024);
    gnb_core->subnetc_node_ring_map = gnb_hash32_create(gnb_core->heap, 1024);

    int64_t now_sec = gnb_timestamp_sec();
    gnb_update_time_seed(gnb_core, now_sec);
    if ( 0 == gnb_core->conf->lite_mode ) {
        gnb_core->ctl_block->core_zone->local_uuid = gnb_core->conf->local_uuid;
        if ( 0==gnb_core->conf->daemon ) {
            if ( 1 == conf->log_verbose ) {
                gnb_core->conf->console_log_level        = 2;
                gnb_core->conf->core_log_level           = 2;
                gnb_core->conf->pf_log_level             = 2;
                gnb_core->conf->main_log_level           = 2;
                gnb_core->conf->node_log_level           = 2;
                gnb_core->conf->index_log_level          = 2;
                gnb_core->conf->index_service_log_level  = 2;
                gnb_core->conf->detect_log_level         = 2;
            }
            if ( 1 == conf->log_trace ) {
                gnb_core->conf->console_log_level        = 3;
                gnb_core->conf->core_log_level           = 3;
                gnb_core->conf->pf_log_level             = 3;
                gnb_core->conf->main_log_level           = 3;
                gnb_core->conf->node_log_level           = 3;
                gnb_core->conf->index_log_level          = 3;
                gnb_core->conf->index_service_log_level  = 3;
                gnb_core->conf->detect_log_level         = 3;
            }
        }
        setup_log_ctx(gnb_core->conf, gnb_core->log);
        gnb_config_safe(gnb_core);
    } else {
        if ( 0==gnb_core->conf->daemon ) {
            if ( 1 == conf->log_verbose ) {
                gnb_core->conf->console_log_level        = 2;
                gnb_core->conf->core_log_level           = 2;
                gnb_core->conf->pf_log_level             = 2;
                gnb_core->conf->main_log_level           = 2;
                gnb_core->conf->node_log_level           = 2;
                gnb_core->conf->index_log_level          = 2;
                gnb_core->conf->index_service_log_level  = 2;
                gnb_core->conf->detect_log_level         = 2;
            }
            if ( 1 == conf->log_trace ) {
                gnb_core->conf->console_log_level        = 3;
                gnb_core->conf->core_log_level           = 3;
                gnb_core->conf->pf_log_level             = 3;
                gnb_core->conf->main_log_level           = 3;
                gnb_core->conf->node_log_level           = 3;
                gnb_core->conf->index_log_level          = 3;
                gnb_core->conf->index_service_log_level  = 3;
                gnb_core->conf->detect_log_level         = 3;
            }
        }
        gnb_config_lite(gnb_core);
        setup_log_ctx(gnb_core->conf, gnb_core->log);
    }
    gnb_log_file_open_rotate(gnb_core->log, 0);
    gnb_log_udp_open(gnb_core->log);
    log_out_description(gnb_core->log);
    void *memory = (void *)gnb_core->ctl_block->entry_table256;
    gnb_ctl_block_build_finish(memory);
    snprintf(gnb_core->ifname, 256, "%s", gnb_core->conf->ifname);
    if ( NULL==gnb_core->local_node ) {
        GNB_ERROR1(gnb_core->log, GNB_LOG_ID_CORE, "local node is miss\n");
        return NULL;
    }
    gnb_core->tun_payload0  = (gnb_payload16_t *)gnb_core->ctl_block->core_zone->tun_payload_block;
    gnb_core->inet_payload0 = (gnb_payload16_t *)gnb_core->ctl_block->core_zone->inet_payload_block;
    gnb_core->tun_payload   = (void *)gnb_core->tun_payload0  + GNB_PAYLOAD_BUFFER_PADDING_SIZE;
    gnb_core->inet_payload  = (void *)gnb_core->inet_payload0 + GNB_PAYLOAD_BUFFER_PADDING_SIZE;

#if defined(__FreeBSD__)
    gnb_core->drv = &gnb_tun_drv_freebsd;
#endif

#if defined(__APPLE__)
    gnb_core->drv = &gnb_tun_drv_darwin;
#endif

#if defined(__OpenBSD__)
    gnb_core->drv = &gnb_tun_drv_openbsd;
#endif

#if defined(__NetBSD__)
    gnb_core->drv = &gnb_tun_drv_netbsd;
#endif

#if defined(__linux__)
    gnb_core->drv = &gnb_tun_drv_linux;
#endif

#if defined(_WIN32)
    if ( GNB_IF_DRV_TYPE_TAP_WINDOWS == conf->if_drv ) {
        gnb_core->drv = &gnb_tun_drv_win32;
    } else if ( GNB_IF_DRV_TYPE_TAP_WINTUN == conf->if_drv ) {
        gnb_core->drv = &gnb_tun_drv_wintun;
    } else {
        gnb_core->drv = &gnb_tun_drv_wintun;
    }
#endif

    gnb_pf_status_strings_init();
    if ( gnb_core->conf->activate_tun ) {
        gnb_core->drv->init_tun(gnb_core);
    }
    if ( gnb_core->conf->activate_node_worker ) {
        gnb_core->node_worker = gnb_worker_init("gnb_node_worker", gnb_core);
    }
    if ( gnb_core->conf->activate_index_worker ) {
        if ( 1 == gnb_core->conf->safe_index && 0 == gnb_core->conf->lite_mode ) {
            gnb_core->index_worker  = gnb_worker_init("gnb_secure_index_worker", gnb_core);
        } else {
            gnb_core->index_worker  = gnb_worker_init("gnb_index_worker", gnb_core);
        }
    }
    if ( gnb_core->conf->activate_detect_worker ) {
        gnb_core->detect_worker = gnb_worker_init("gnb_detect_worker", gnb_core);
    }
    if ( gnb_core->conf->activate_index_service_worker ) {
        if ( 1 == gnb_core->conf->safe_index ) {
            gnb_core->index_service_worker  = gnb_worker_init("gnb_secure_index_service_worker", gnb_core);
        } else {
            gnb_core->index_service_worker  = gnb_worker_init("gnb_index_service_worker", gnb_core);            
        }
    }
    if ( gnb_core->conf->pf_worker_num > 0 ) {
        gnb_core->pf_worker_ring = (gnb_worker_ring_t *)gnb_heap_alloc(gnb_core->heap, sizeof(gnb_worker_ring_t) + sizeof(gnb_worker_t)*gnb_core->conf->pf_worker_num);
        gnb_core->pf_worker_ring->size = gnb_core->conf->pf_worker_num;
        for ( gnb_core->pf_worker_ring->cur_idx=0; gnb_core->pf_worker_ring->cur_idx < gnb_core->pf_worker_ring->size; gnb_core->pf_worker_ring->cur_idx++ ) {
            gnb_core->pf_worker_ring->worker[gnb_core->pf_worker_ring->cur_idx] = gnb_worker_init("gnb_pf_worker", gnb_core);
        }
        gnb_core->pf_worker_ring->cur_idx=0;
    } else {
        gnb_core->pf_worker_ring = (gnb_worker_ring_t *)gnb_heap_alloc(gnb_core->heap, sizeof(gnb_worker_ring_t) );
        gnb_core->pf_worker_ring->size = 0;
    }
    gnb_core->primary_worker = gnb_worker_init("gnb_primary_worker", gnb_core);
    if ( GNB_CORE_RESTORE == gnb_core->conf->restore ) {
        //Add Log ... ...
        goto finish;
    }
    int i;
    struct sockaddr_in6 sockaddr6;
    struct sockaddr_in  sockaddr;
    socklen_t sockaddr_len;
    if ( gnb_core->conf->udp_socket_type & GNB_ADDR_TYPE_IPV6 ) {
        for ( i=0; i < gnb_core->conf->udp6_socket_num; i++ ) {
            gnb_core->udp_ipv6_sockets[i] = socket(AF_INET6, SOCK_DGRAM, 0);
            gnb_bind_udp_socket_ipv6(gnb_core->udp_ipv6_sockets[i], gnb_core->conf->listen_address6_string,  gnb_core->conf->udp6_ports[i]);
            sockaddr_len = sizeof(struct sockaddr_in6);
            getsockname( gnb_core->udp_ipv6_sockets[i], (struct sockaddr *)&sockaddr6, &sockaddr_len );
            gnb_core->conf->udp6_ports[i] = ntohs(sockaddr6.sin6_port);
            GNB_LOG1(gnb_core->log,GNB_LOG_ID_MAIN_WORKER, "bind addr6 [%s:%d]\n", gnb_core->conf->listen_address6_string, gnb_core->conf->udp6_ports[i]);
        }
    }
    if ( gnb_core->conf->udp_socket_type & GNB_ADDR_TYPE_IPV4 ) {
        for ( i=0; i < gnb_core->conf->udp4_socket_num; i++ ) {
            gnb_core->udp_ipv4_sockets[i] = socket(AF_INET, SOCK_DGRAM, 0);
            gnb_bind_udp_socket_ipv4(gnb_core->udp_ipv4_sockets[i], gnb_core->conf->listen_address4_string, gnb_core->conf->udp4_ports[i]);
            if ( 0==gnb_core->conf->udp4_ports[i] ) {
                sockaddr_len = sizeof(struct sockaddr_in);
                getsockname( gnb_core->udp_ipv4_sockets[i], (struct sockaddr *)&sockaddr, &sockaddr_len );
                gnb_core->conf->udp4_ports[i] = ntohs(sockaddr.sin_port);
            }
            gnb_core->conf->udp4_ext_ports[i] = gnb_core->conf->udp4_ports[i];
            GNB_LOG1(gnb_core->log,GNB_LOG_ID_MAIN_WORKER, "bind addr4[%s:%d]\n", gnb_core->conf->listen_address4_string, gnb_core->conf->udp4_ports[i]);
        }
    }
#ifdef __UNIX_LIKE_OS__
    //尝试绑定网卡
    bind_socket_if(gnb_core);
#endif

finish:
    return gnb_core;
}

gnb_core_t* gnb_core_index_service_create(gnb_conf_t *conf) {
    gnb_core_t *gnb_core;
    gnb_heap_t *heap = gnb_heap_create(conf->max_heap_fragment);
    gnb_core = gnb_heap_alloc(heap, sizeof(gnb_core_t));
    memset(gnb_core, 0, sizeof(gnb_core_t));
    gnb_core->heap = heap;
    gnb_core->heap_lru32 = gnb_heap_create(conf->index_service_lru_size + 128);
    ctl_block_create(gnb_core, conf);
    gnb_core->conf = &gnb_core->ctl_block->conf_zone->conf_st;
    memcpy(gnb_core->conf, conf, sizeof(gnb_conf_t));
    gnb_core->ed25519_private_key = gnb_core->ctl_block->core_zone->ed25519_private_key;
    gnb_core->ed25519_public_key  = gnb_core->ctl_block->core_zone->ed25519_public_key;
    gnb_core->ifname = (char *)gnb_core->ctl_block->core_zone->ifname;
    gnb_core->if_device_string = (char *)gnb_core->ctl_block->core_zone->if_device_string;
    gnb_core->log =  &gnb_core->ctl_block->core_zone->log_ctx_st;
    gnb_log_ctx_init(gnb_core->log);
    if ( 0 == conf->daemon ) {
        if ( 1 == conf->log_verbose ) {
            gnb_core->conf->console_log_level        = 2;
            gnb_core->conf->core_log_level           = 2;
            gnb_core->conf->pf_log_level             = 2;
            gnb_core->conf->main_log_level           = 2;
            gnb_core->conf->node_log_level           = 2;
            gnb_core->conf->index_log_level          = 2;
            gnb_core->conf->index_service_log_level  = 2;
            gnb_core->conf->detect_log_level         = 2;
        }
        if ( 1 == conf->log_trace ) {
            gnb_core->conf->console_log_level        = 3;
            gnb_core->conf->core_log_level           = 3;
            gnb_core->conf->pf_log_level             = 3;
            gnb_core->conf->main_log_level           = 3;
            gnb_core->conf->node_log_level           = 3;
            gnb_core->conf->index_log_level          = 3;
            gnb_core->conf->index_service_log_level  = 3;
            gnb_core->conf->detect_log_level         = 3;
        }
        if ( 1 == gnb_core->conf->if_dump ) {
            gnb_core->conf->console_log_level        = 3;
            gnb_core->conf->pf_log_level             = 3;
        }
    }
    setup_log_ctx(gnb_core->conf, gnb_core->log);
    gnb_log_file_open_rotate(gnb_core->log, 0);
    gnb_log_udp_open(gnb_core->log);
    log_out_description(gnb_core->log);
    void *memory = (void *)gnb_core->ctl_block->entry_table256;
    gnb_ctl_block_build_finish(memory);
    snprintf(gnb_core->ifname,256,"%s", gnb_core->conf->ifname);
    gnb_core->tun_payload0  = (gnb_payload16_t *)gnb_core->ctl_block->core_zone->tun_payload_block;
    gnb_core->inet_payload0 = (gnb_payload16_t *)gnb_core->ctl_block->core_zone->inet_payload_block;
    gnb_core->tun_payload  = gnb_core->tun_payload0  + GNB_PAYLOAD_BUFFER_PADDING_SIZE;
    gnb_core->inet_payload = gnb_core->inet_payload0 + GNB_PAYLOAD_BUFFER_PADDING_SIZE;
    gnb_core->index_service_worker  = gnb_worker_init("gnb_index_service_worker",  gnb_core);
    gnb_core->primary_worker        = gnb_worker_init("gnb_primary_worker", gnb_core);

    int i;
    struct sockaddr_in6 sockaddr6;
    struct sockaddr_in  sockaddr;
    socklen_t sockaddr_len;
    if ( gnb_core->conf->udp_socket_type & GNB_ADDR_TYPE_IPV6 ) {
        for ( i=0; i < gnb_core->conf->udp6_socket_num; i++ ) {
            gnb_core->udp_ipv6_sockets[i] = socket(AF_INET6, SOCK_DGRAM, 0);
            gnb_bind_udp_socket_ipv6(gnb_core->udp_ipv6_sockets[i], gnb_core->conf->listen_address6_string,  gnb_core->conf->udp6_ports[i]);
            sockaddr_len = sizeof(struct sockaddr_in6);
            getsockname( gnb_core->udp_ipv6_sockets[i], (struct sockaddr *)&sockaddr6, &sockaddr_len );
            gnb_core->conf->udp6_ports[i] = ntohs(sockaddr6.sin6_port);
            GNB_LOG1(gnb_core->log,GNB_LOG_ID_MAIN_WORKER, "bind addr6 [%s:%d]\n", gnb_core->conf->listen_address6_string, gnb_core->conf->udp6_ports[i]);
        }
    }
    if ( gnb_core->conf->udp_socket_type & GNB_ADDR_TYPE_IPV4 ) {
        for ( i=0; i < gnb_core->conf->udp4_socket_num; i++ ) {
            gnb_core->udp_ipv4_sockets[i] = socket(AF_INET, SOCK_DGRAM, 0);
            gnb_bind_udp_socket_ipv4(gnb_core->udp_ipv4_sockets[i], gnb_core->conf->listen_address4_string, gnb_core->conf->udp4_ports[i]);
            if ( 0==gnb_core->conf->udp4_ports[i] ) {
                sockaddr_len = sizeof(struct sockaddr_in);
                getsockname( gnb_core->udp_ipv4_sockets[i], (struct sockaddr *)&sockaddr, &sockaddr_len );
                gnb_core->conf->udp4_ports[i] = ntohs(sockaddr.sin_port);
            }
            gnb_core->conf->udp4_ext_ports[i] = gnb_core->conf->udp4_ports[i];
            GNB_LOG1(gnb_core->log,GNB_LOG_ID_MAIN_WORKER, "bind addr4[%s:%d]\n", gnb_core->conf->listen_address4_string, gnb_core->conf->udp4_ports[i]);
        }
    }
#ifdef __UNIX_LIKE_OS__
    //尝试绑定网卡
    bind_socket_if(gnb_core);
#endif
    return gnb_core;
}

void gnb_core_release(gnb_core_t *gnb_core) {
    int i;
    gnb_heap_t *heap = gnb_core->heap;
    gnb_core->primary_worker->release(gnb_core->primary_worker);
    if ( gnb_core->conf->public_index_service ) {
        goto PUBLIC_INDEX_RELEASE;
    }
    if ( gnb_core->conf->activate_tun ) {
        for ( i=0; i<gnb_core->pf_worker_ring->size; i++ ) {
            //在释放 pf_worker_ring 同时时也包括了释放其中的 pf_core
            gnb_core->pf_worker_ring->worker[i]->release(gnb_core->pf_worker_ring->worker[i]);
        }
        gnb_core->drv->release_tun(gnb_core);
    }
    if ( gnb_core->conf->activate_index_worker ) {
        gnb_core->index_worker->release(gnb_core->index_worker);
    }
    if ( gnb_core->conf->activate_detect_worker ) {
        gnb_core->detect_worker->release(gnb_core->detect_worker);
    }
    if ( gnb_core->conf->activate_index_service_worker ) {
        gnb_core->index_service_worker->release(gnb_core->index_service_worker);
    }
    if ( gnb_core->conf->activate_node_worker ) {
        gnb_core->node_worker->release(gnb_core->node_worker);
    }
PUBLIC_INDEX_RELEASE:
    if ( gnb_core->conf->activate_index_service_worker ) {
        gnb_core->index_service_worker->release(gnb_core->index_service_worker);
    }
	
    gnb_heap_release(gnb_core->heap_lru32);

	gnb_log_udp_close(gnb_core->log);
	gnb_log_close(gnb_core->log);

    ctl_block_release(gnb_core);
    gnb_heap_free(gnb_core->heap, gnb_core);
    gnb_heap_release(heap);
}

void gnb_core_index_service_start(gnb_core_t *gnb_core) {
    int ret;
    GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE,"GNB Public Index Service Start.....\n");
	gnb_core->ctl_block->core_zone->gnb_core_flag = GNB_CORE_FLAG_START;
    gnb_core->index_service_worker->start(gnb_core->index_service_worker);
    GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE,"%s start\n", gnb_core->index_service_worker->name);
    gnb_core->primary_worker->start(gnb_core->primary_worker);
    GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE,"%s start\n", gnb_core->primary_worker->name);
}

void gnb_core_start(gnb_core_t *gnb_core) {
    int ret;
    int i;
    char address_string1[GNB_IP6_PORT_STRING_SIZE];
    GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE, "Start.....\n");
    gnb_setup_env(gnb_core);
    update_node_crypto_key(gnb_core, 1);
    if ( gnb_core->conf->activate_tun ) {
        ret = gnb_core->drv->open_tun(gnb_core);
        if ( 0!=ret ) {
            if ( -1 == ret ) {
                GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE, "if[%s] already open\n", gnb_core->ifname);
            } else {
                GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE, "if[%s] error\n", gnb_core->ifname);
            }
            return;
        }
        GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE, "if[%s] opened\n", gnb_core->ifname);
        GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE, "node[%llu] ipv4[%s]\n",
                 gnb_core->local_node->uuid64,
                 gnb_in4_addr_str(&gnb_core->local_node->tun_addr4, address_string1,0)
        );
        for ( i=0; i<gnb_core->pf_worker_ring->size; i++ ) {
            gnb_core->pf_worker_ring->worker[i]->start(gnb_core->pf_worker_ring->worker[i]);
            GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE, "start packet filter worker [%s]\n", gnb_core->pf_worker_ring->worker[i]->name);
        }
    }
    if ( gnb_core->conf->activate_index_worker ) {
        gnb_core->index_worker->start(gnb_core->index_worker);
        GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE,"%s start\n", gnb_core->index_worker->name);
    }
    if ( gnb_core->conf->activate_detect_worker ) {
        gnb_core->detect_worker->start(gnb_core->detect_worker);
        GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE,"%s start\n", gnb_core->detect_worker->name);
    }
    if ( gnb_core->conf->activate_index_service_worker ) {
        gnb_core->index_service_worker->start(gnb_core->index_service_worker);
        GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE,"%s start\n", gnb_core->index_service_worker->name);
    }
    if ( gnb_core->conf->activate_node_worker ) {
        gnb_core->node_worker->start(gnb_core->node_worker);
        GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE,"%s start\n", gnb_core->node_worker->name);
    }
    gnb_core->primary_worker->start(gnb_core->primary_worker);
    GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE,"%s start\n", gnb_core->primary_worker->name);
}

void gnb_core_stop(gnb_core_t *gnb_core) {
	int i;
	//注意: primary_worker 在 Windows 平台上有两个线程
	gnb_core->primary_worker->stop(gnb_core->primary_worker);

#ifdef __UNIX_LIKE_OS__
	gnb_worker_wait_worker_stoped(gnb_core, gnb_core->primary_worker);
#endif

	if ( gnb_core->conf->activate_tun ) {
		for ( i=0; i<gnb_core->pf_worker_ring->size; i++ ) {
			gnb_core->pf_worker_ring->worker[i]->stop(gnb_core->pf_worker_ring->worker[i]);
			gnb_worker_wait_worker_stoped(gnb_core, gnb_core->pf_worker_ring->worker[i]);
		}
		gnb_core->drv->close_tun(gnb_core);
		GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE,"if[%s] closeed\n", gnb_core->ifname);
	}
	if ( gnb_core->conf->activate_index_worker ) {
		gnb_core->index_worker->stop(gnb_core->index_worker);
		gnb_worker_wait_worker_stoped(gnb_core, gnb_core->index_worker);
	}
	if ( gnb_core->conf->activate_detect_worker ) {
		gnb_core->detect_worker->stop(gnb_core->detect_worker);
		gnb_worker_wait_worker_stoped(gnb_core, gnb_core->detect_worker);
	}
	if ( gnb_core->conf->activate_index_service_worker ) {
		gnb_core->index_service_worker->stop(gnb_core->index_service_worker);
		gnb_worker_wait_worker_stoped(gnb_core, gnb_core->index_service_worker);
	}
	if ( gnb_core->conf->activate_node_worker ) {
		gnb_core->node_worker->stop(gnb_core->node_worker);
		gnb_worker_wait_worker_stoped(gnb_core, gnb_core->node_worker);
	}

	if ( GNB_CORE_FLAG_RESTART == gnb_core->ctl_block->core_zone->gnb_core_flag ) {
		goto finish;
	}
	
#ifdef __UNIX_LIKE_OS__
	for ( i=0; i<gnb_core->conf->udp6_socket_num; i++ ) {
		close(gnb_core->udp_ipv6_sockets[i]);
	}
	for ( i=0; i<gnb_core->conf->udp4_socket_num; i++ ) {
		close(gnb_core->udp_ipv4_sockets[i]);
	}
#endif
	
#ifdef _WIN32
	for ( i=0; i<gnb_core->conf->udp6_socket_num; i++ ) {
		closesocket(gnb_core->udp_ipv6_sockets[i]);
	}
	for ( i=0; i<gnb_core->conf->udp4_socket_num; i++ ) {
		closesocket(gnb_core->udp_ipv4_sockets[i]);
	}
#endif

finish:
	GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE,"gnb_core_stop Finish!!\n");
}

void gnb_hot_restart_prepare(gnb_core_t *gnb_core_new,gnb_core_t *gnb_core) {
	gnb_uint64_t i;
    GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE, "===-- GNB Hot Restart Data Restore --===\n");
    if ( 1 == gnb_core->conf->public_index_service || 1 == gnb_core_new->conf->public_index_service ) {
        return;
    }
    // restore socket
    uint8_t socket_num;
    if ( gnb_core_new->conf->udp6_socket_num <= gnb_core->conf->udp6_socket_num ) {
        socket_num = gnb_core_new->conf->udp6_socket_num;
    } else {
        socket_num = gnb_core->conf->udp6_socket_num;
    }
    for ( i=0; i<socket_num; i++ ) {
        gnb_core_new->udp_ipv6_sockets[i] = gnb_core->udp_ipv6_sockets[i];
    }
    for ( i=socket_num; i < gnb_core->conf->udp6_socket_num; i++ ) {
        #ifdef __UNIX_LIKE_OS__
        close(gnb_core->udp_ipv6_sockets[i]);
        #endif
        #ifdef _WIN32
        closesocket(gnb_core->udp_ipv6_sockets[i]);
        #endif
        gnb_core->udp_ipv6_sockets[i] = -1;
    }

    if ( gnb_core_new->conf->udp4_socket_num <= gnb_core->conf->udp4_socket_num ) {
        socket_num = gnb_core_new->conf->udp4_socket_num;
    } else {
        socket_num = gnb_core->conf->udp4_socket_num;
    }
    for ( i=0; i<socket_num; i++ ) {
        gnb_core_new->udp_ipv4_sockets[i] = gnb_core->udp_ipv4_sockets[i];
    }
    for ( i=socket_num; i < gnb_core->conf->udp4_socket_num; i++ ) {
        #ifdef __UNIX_LIKE_OS__
        close(gnb_core->udp_ipv4_sockets[i]);
        #endif
        #ifdef _WIN32
        closesocket(gnb_core->udp_ipv4_sockets[i]);
        #endif
        gnb_core->udp_ipv4_sockets[i] = -1;
    }
    /*
     遍历 gnb_core 的节点, 如果一个节点不存在于 gnb_core_new ,那么跳过该节点
     */
	gnb_uint64_t num = gnb_core->ctl_block->node_zone->node_num;
    if ( 0 == num ) {
        return;
    }
    gnb_node_t *node;
    gnb_node_t *new_core_node;
    for ( i=0; i<num; i++ ) {
        node = &gnb_core->ctl_block->node_zone->node[i];
		if ( gnb_core->conf->local_uuid == node->uuid64 ) {
            continue;
        }
        if ( !( (GNB_NODE_STATUS_IPV6_PONG | GNB_NODE_STATUS_IPV4_PONG) & node->udp_addr_status ) ) {
            GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE, "Hot Restart Skip node[%llu]\n", node->uuid64);
            continue;
        }
        new_core_node = GNB_HASH32_UINT64_GET_PTR(gnb_core_new->uuid_node_map, node->uuid64);
        if ( NULL==new_core_node ) {
            GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE, "Hot Restart Remove node[%llu]\n", node->uuid64);
            continue;
        }
        GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE, "Hot Restart Resume node[%llu]\n", node->uuid64);
        new_core_node->in_bytes  = node->in_bytes;
        new_core_node->out_bytes = node->out_bytes;
        memcpy(&new_core_node->udp_sockaddr6, &node->udp_sockaddr6, sizeof(struct sockaddr_in6));
        memcpy(&new_core_node->udp_sockaddr4, &node->udp_sockaddr4, sizeof(struct sockaddr_in));
        new_core_node->socket6_idx = (node->socket6_idx < gnb_core_new->conf->udp6_socket_num) ? node->socket6_idx : 0;
        new_core_node->socket4_idx = (node->socket4_idx < gnb_core_new->conf->udp4_socket_num) ? node->socket4_idx : 0;
        memcpy(&new_core_node->static_address_block, &node->static_address_block, sizeof(new_core_node->static_address_block));
        memcpy(&new_core_node->dynamic_address_block, &node->dynamic_address_block, sizeof(new_core_node->dynamic_address_block));
        memcpy(&new_core_node->resolv_address_block, &node->resolv_address_block, sizeof(new_core_node->resolv_address_block));
        memcpy(&new_core_node->push_address_block, &node->push_address_block, sizeof(new_core_node->push_address_block));
        memcpy(&new_core_node->available_address6_list3_block, &node->available_address6_list3_block, sizeof(new_core_node->available_address6_list3_block));
        memcpy(&new_core_node->available_address4_list3_block, &node->available_address4_list3_block, sizeof(new_core_node->available_address4_list3_block));
        new_core_node->udp_addr_status = node->udp_addr_status;
    }
    GNB_LOG1(gnb_core->log, GNB_LOG_ID_CORE, "===-- GNB Hot Restart Data Restore finish --===\n");
}
