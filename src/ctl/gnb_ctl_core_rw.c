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
#include <string.h>
#include <strings.h>
#include <inttypes.h>

#if defined(__linux__) || defined(__FreeBSD__) || defined(__APPLE__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <arpa/inet.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "gnb_conf_type.h"
#include "gnb_node_type.h"
#include "gnb_address.h"
#include "gnb_binary.h"
#include "gnb_ctl_block.h"
#include "gnb_arg_list.h"

#define GNB_LOG_LEVEL_UNSET 0xFF

#define GNB_SWITCH_STR(v) ((v) ? "on" : "off")
#define GNB_PARSE_SWITCH(s) ( \
    (!strcmp((s), "1") || !strcasecmp((s), "on"))  ? 1 : \
    (!strcmp((s), "0") || !strcasecmp((s), "off")) ? 0 : -1 \
)

static int parse_log_level(const char *data, uint8_t *out_level) {
    if ( !strcasecmp(data, "unset") ) {
        *out_level = GNB_LOG_LEVEL_UNSET;
        return 0;
    }
    char *endptr;
    long lvl = strtol(data, &endptr, 10);
    if ( *endptr != '\0' || lvl < 0 || lvl > 5 ) {
        return -1;
    }
    *out_level = (uint8_t)lvl;
    return 0;
}

static void print_log_level(const char *key, uint8_t level) {
    if ( GNB_LOG_LEVEL_UNSET == level ) {
        printf("%s=unset\n", key);
    } else {
        printf("%s=%u\n", key, level);
    }
}

void gnb_ctl_core_restart(gnb_ctl_block_t *ctl_block) {
    ctl_block->core_zone->gnb_core_flag = GNB_CORE_FLAG_RESTART;
    printf("core.flag=%u\n", ctl_block->core_zone->gnb_core_flag);
}

static void set_core_restart(gnb_ctl_block_t *ctl_block, char *data) {
    if ( !strcmp(data, "2") || !strcasecmp(data, "restart") ) {
        gnb_ctl_core_restart(ctl_block);
    }
}

static void set_log_ctl(gnb_ctl_block_t *ctl_block, char *key, char *data) {
    char *endptr;
    uint8_t lvl;

    /* 1. 文件日志相关 */
    if ( !memcmp("core.log.file.path", key, sizeof("core.log.file.path")-1) ) {
        snprintf(ctl_block->conf_zone->conf_st.log_path, PATH_MAX, "%s", data);
        ctl_block->core_zone->log_trigger |= (GNB_LOG_TRIGGER_SETUP | GNB_LOG_TRIGGER_ROTATE);
        return;
    }
    if ( !memcmp("core.log.file.std", key, sizeof("core.log.file.std")-1) ) {
        snprintf(ctl_block->core_zone->log_ctx_st.log_file_name_std, PATH_MAX+NAME_MAX, "%s", data);
        ctl_block->core_zone->log_ctx_st.output_type |= GNB_LOG_OUTPUT_FILE;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_ROTATE;
        return;
    }
    if ( !memcmp("core.log.file.debug", key, sizeof("core.log.file.debug")-1) ) {
        snprintf(ctl_block->core_zone->log_ctx_st.log_file_name_debug, PATH_MAX+NAME_MAX, "%s", data);
        ctl_block->core_zone->log_ctx_st.output_type |= GNB_LOG_OUTPUT_FILE;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_ROTATE;
        return;
    }
    if ( !memcmp("core.log.file.error", key, sizeof("core.log.file.error")-1) ) {
        snprintf(ctl_block->core_zone->log_ctx_st.log_file_name_error, PATH_MAX+NAME_MAX, "%s", data);
        ctl_block->core_zone->log_ctx_st.output_type |= GNB_LOG_OUTPUT_FILE;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_ROTATE;
        return;
    }
    if ( !memcmp("core.log.file.rotate", key, sizeof("core.log.file.rotate")-1) ) {
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_ROTATE;
        return;
    }

    /* 2. UDP 日志相关 */
    if ( !memcmp("core.log.udp_addr4", key, sizeof("core.log.udp_addr4")-1) ) {
        struct in_addr test_addr;
        if ( inet_pton(AF_INET, data, &test_addr) <= 0 ) {
            fprintf(stderr, "invalid ipv4 address: '%s'\n", data);
            return;
        }
        uint16_t port = ntohs(ctl_block->core_zone->log_ctx_st.port4);
        if ( 0 == port ) {
            port = 9000;
        }
        snprintf(ctl_block->conf_zone->conf_st.log_udp_sockaddress4_string,
                 sizeof(ctl_block->conf_zone->conf_st.log_udp_sockaddress4_string),
                 "%s:%u", data, port);
        memcpy(ctl_block->core_zone->log_ctx_st.addr4, &test_addr.s_addr, 4);
        ctl_block->core_zone->log_ctx_st.port4 = htons(port);
        ctl_block->core_zone->log_ctx_st.output_type |= GNB_LOG_OUTPUT_UDP;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }
    if ( !memcmp("core.log.udp_port4", key, sizeof("core.log.udp_port4")-1) ) {
        long port = strtol(data, &endptr, 10);
        if ( *endptr != '\0' || port <= 0 || port > 65535 ) {
            fprintf(stderr, "invalid udp_port: '%s', valid range is 1-65535\n", data);
            return;
        }
        ctl_block->core_zone->log_ctx_st.port4 = htons((uint16_t)port);
        char ip[16];
        inet_ntop(AF_INET, ctl_block->core_zone->log_ctx_st.addr4, ip, sizeof(ip));
        snprintf(ctl_block->conf_zone->conf_st.log_udp_sockaddress4_string,
                 sizeof(ctl_block->conf_zone->conf_st.log_udp_sockaddress4_string),
                 "%s:%ld", ip, port);
        ctl_block->core_zone->log_ctx_st.output_type |= GNB_LOG_OUTPUT_UDP;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }
    if ( !memcmp("core.log.udp_type", key, sizeof("core.log.udp_type")-1) ) {
        long type = strtol(data, &endptr, 10);
        if ( *endptr != '\0' || (type != 0 && type != 1) ) {
            fprintf(stderr, "invalid udp_type: '%s', must be 0 (text) or 1 (binary)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.log_udp_type = (uint8_t)type;
        ctl_block->core_zone->log_ctx_st.log_udp_type = (uint8_t)type;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }

    /* 3. 通道日志等级 */
    if ( !memcmp("core.log.console_level", key, sizeof("core.log.console_level")-1) ) {
        if ( parse_log_level(data, &lvl) != 0 ) {
            fprintf(stderr, "invalid console_level: '%s' (0-5 or unset)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.console_log_level = lvl;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }
    if ( !memcmp("core.log.file_level", key, sizeof("core.log.file_level")-1) ) {
        if ( parse_log_level(data, &lvl) != 0 ) {
            fprintf(stderr, "invalid file_level: '%s' (0-5 or unset)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.file_log_level = lvl;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }
    if ( !memcmp("core.log.udp_level", key, sizeof("core.log.udp_level")-1) ) {
        if ( parse_log_level(data, &lvl) != 0 ) {
            fprintf(stderr, "invalid udp_level: '%s' (0-5 or unset)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.udp_log_level = lvl;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }

    /* 4. 各子模块细粒度等级设置 */
    if ( !memcmp("core.log.core_log_level", key, sizeof("core.log.core_log_level")-1) ) {
        if ( parse_log_level(data, &lvl) != 0 ) {
            fprintf(stderr, "invalid core_log_level: '%s' (0-5 or unset)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.core_log_level = lvl;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }
    if ( !memcmp("core.log.pf_log_level", key, sizeof("core.log.pf_log_level")-1) ) {
        if ( parse_log_level(data, &lvl) != 0 ) {
            fprintf(stderr, "invalid pf_log_level: '%s' (0-5 or unset)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.pf_log_level = lvl;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }
    if ( !memcmp("core.log.main_log_level", key, sizeof("core.log.main_log_level")-1) ) {
        if ( parse_log_level(data, &lvl) != 0 ) {
            fprintf(stderr, "invalid main_log_level: '%s' (0-5 or unset)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.main_log_level = lvl;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }
    if ( !memcmp("core.log.node_log_level", key, sizeof("core.log.node_log_level")-1) ) {
        if ( parse_log_level(data, &lvl) != 0 ) {
            fprintf(stderr, "invalid node_log_level: '%s' (0-5 or unset)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.node_log_level = lvl;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }
    if ( !memcmp("core.log.index_log_level", key, sizeof("core.log.index_log_level")-1) ) {
        if ( parse_log_level(data, &lvl) != 0 ) {
            fprintf(stderr, "invalid index_log_level: '%s' (0-5 or unset)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.index_log_level = lvl;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }
    if ( !memcmp("core.log.index_service_log_level", key, sizeof("core.log.index_service_log_level")-1) ) {
        if ( parse_log_level(data, &lvl) != 0 ) {
            fprintf(stderr, "invalid index_service_log_level: '%s' (0-5 or unset)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.index_service_log_level = lvl;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }
    if ( !memcmp("core.log.node_detect_log_level", key, sizeof("core.log.node_detect_log_level")-1) ) {
        if ( parse_log_level(data, &lvl) != 0 ) {
            fprintf(stderr, "invalid node_detect_log_level: '%s' (0-5 or unset)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.detect_log_level = lvl;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }

    /* 5. 开关量（on|off|1|0） */
    if ( !memcmp("core.log.verbose", key, sizeof("core.log.verbose")-1) ) {
        int sw = GNB_PARSE_SWITCH(data);
        if ( sw < 0 ) {
            fprintf(stderr, "invalid verbose switch: '%s' (use on|off or 1|0)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.log_verbose = (uint8_t)sw;
        uint8_t level = sw ? 2 : 1;
        ctl_block->conf_zone->conf_st.console_log_level       = level;
        ctl_block->conf_zone->conf_st.core_log_level          = level;
        ctl_block->conf_zone->conf_st.pf_log_level            = level;
        ctl_block->conf_zone->conf_st.main_log_level          = level;
        ctl_block->conf_zone->conf_st.node_log_level          = level;
        ctl_block->conf_zone->conf_st.index_log_level         = level;
        ctl_block->conf_zone->conf_st.index_service_log_level = level;
        ctl_block->conf_zone->conf_st.detect_log_level        = level;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }
    if ( !memcmp("core.log.trace", key, sizeof("core.log.trace")-1) ) {
        int sw = GNB_PARSE_SWITCH(data);
        if ( sw < 0 ) {
            fprintf(stderr, "invalid trace switch: '%s' (use on|off or 1|0)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.log_trace = (uint8_t)sw;
        uint8_t level = sw ? 3 : 1;
        ctl_block->conf_zone->conf_st.console_log_level       = level;
        ctl_block->conf_zone->conf_st.core_log_level          = level;
        ctl_block->conf_zone->conf_st.pf_log_level            = level;
        ctl_block->conf_zone->conf_st.main_log_level          = level;
        ctl_block->conf_zone->conf_st.node_log_level          = level;
        ctl_block->conf_zone->conf_st.index_log_level         = level;
        ctl_block->conf_zone->conf_st.index_service_log_level = level;
        ctl_block->conf_zone->conf_st.detect_log_level        = level;
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }
    if ( !memcmp("core.log.ifdump", key, sizeof("core.log.ifdump")-1) ) {
        int sw = GNB_PARSE_SWITCH(data);
        if ( sw < 0 ) {
            fprintf(stderr, "invalid ifdump switch: '%s' (use on|off or 1|0)\n", data);
            return;
        }
        ctl_block->conf_zone->conf_st.if_dump = (uint8_t)sw;
        if ( sw ) {
            ctl_block->conf_zone->conf_st.console_log_level = 3;
            ctl_block->conf_zone->conf_st.pf_log_level      = 3;
        }
        ctl_block->core_zone->log_trigger |= GNB_LOG_TRIGGER_SETUP;
        return;
    }
}

void gnb_ctl_core_write(gnb_ctl_block_t *ctl_block, gnb_arg_list_t *core_rw_arg_list) {
    int i;
    int num;
    char key[128+1];
    char data[128+1];
    for ( i=0; i < core_rw_arg_list->argc; i++ ) {
        num = sscanf(core_rw_arg_list->argv[i], "%128[^=]=%128s", key, data);
        if ( 2 != num ) {
            continue;
        }
        if ( !memcmp("core.flag", key, sizeof("core.flag")) ) {
            set_core_restart(ctl_block, data);
        }
        if ( !memcmp("core.log", key, sizeof("core.log")-1) ) {
            set_log_ctl(ctl_block, key, data);
        }
    }
}

/* 读取单一节点逻辑 */
static int read_single_key(gnb_ctl_block_t *ctl_block, const char *key) {
    char ip[16];
    if ( !strcmp("core.flag", key) ) {
        printf("core.flag=%u\n", ctl_block->core_zone->gnb_core_flag);
        return 0;
    }
    if ( !strcmp("core.log.file.path", key) ) {
        printf("core.log.file.path=%s\n", ctl_block->conf_zone->conf_st.log_path);
        return 0;
    }
    if ( !strcmp("core.log.file.std", key) ) {
        printf("core.log.file.std=%s\n", ctl_block->core_zone->log_ctx_st.log_file_name_std);
        return 0;
    }
    if ( !strcmp("core.log.file.debug", key) ) {
        printf("core.log.file.debug=%s\n", ctl_block->core_zone->log_ctx_st.log_file_name_debug);
        return 0;
    }
    if ( !strcmp("core.log.file.error", key) ) {
        printf("core.log.file.error=%s\n", ctl_block->core_zone->log_ctx_st.log_file_name_error);
        return 0;
    }
    if ( !strcmp("core.log.udp_addr4", key) ) {
        inet_ntop(AF_INET, ctl_block->core_zone->log_ctx_st.addr4, ip, sizeof(ip));
        printf("core.log.udp_addr4=%s\n", ip);
        return 0;
    }
    if ( !strcmp("core.log.udp_port4", key) ) {
        printf("core.log.udp_port4=%u\n", ntohs(ctl_block->core_zone->log_ctx_st.port4));
        return 0;
    }
    if ( !strcmp("core.log.udp_type", key) ) {
        printf("core.log.udp_type=%u\n", ctl_block->conf_zone->conf_st.log_udp_type);
        return 0;
    }
    if ( !strcmp("core.log.console_level", key) ) {
        print_log_level("core.log.console_level", ctl_block->conf_zone->conf_st.console_log_level);
        return 0;
    }
    if ( !strcmp("core.log.file_level", key) ) {
        print_log_level("core.log.file_level", ctl_block->conf_zone->conf_st.file_log_level);
        return 0;
    }
    if ( !strcmp("core.log.udp_level", key) ) {
        print_log_level("core.log.udp_level", ctl_block->conf_zone->conf_st.udp_log_level);
        return 0;
    }
    if ( !strcmp("core.log.core_log_level", key) ) {
        print_log_level("core.log.core_log_level", ctl_block->conf_zone->conf_st.core_log_level);
        return 0;
    }
    if ( !strcmp("core.log.pf_log_level", key) ) {
        print_log_level("core.log.pf_log_level", ctl_block->conf_zone->conf_st.pf_log_level);
        return 0;
    }
    if ( !strcmp("core.log.main_log_level", key) ) {
        print_log_level("core.log.main_log_level", ctl_block->conf_zone->conf_st.main_log_level);
        return 0;
    }
    if ( !strcmp("core.log.node_log_level", key) ) {
        print_log_level("core.log.node_log_level", ctl_block->conf_zone->conf_st.node_log_level);
        return 0;
    }
    if ( !strcmp("core.log.index_log_level", key) ) {
        print_log_level("core.log.index_log_level", ctl_block->conf_zone->conf_st.index_log_level);
        return 0;
    }
    if ( !strcmp("core.log.index_service_log_level", key) ) {
        print_log_level("core.log.index_service_log_level", ctl_block->conf_zone->conf_st.index_service_log_level);
        return 0;
    }
    if ( !strcmp("core.log.node_detect_log_level", key) ) {
        print_log_level("core.log.node_detect_log_level", ctl_block->conf_zone->conf_st.detect_log_level);
        return 0;
    }
    if ( !strcmp("core.log.verbose", key) ) {
        printf("core.log.verbose=%s\n", GNB_SWITCH_STR(ctl_block->conf_zone->conf_st.log_verbose));
        return 0;
    }
    if ( !strcmp("core.log.trace", key) ) {
        printf("core.log.trace=%s\n", GNB_SWITCH_STR(ctl_block->conf_zone->conf_st.log_trace));
        return 0;
    }
    if ( !strcmp("core.log.ifdump", key) ) {
        printf("core.log.ifdump=%s\n", GNB_SWITCH_STR(ctl_block->conf_zone->conf_st.if_dump));
        return 0;
    }
    return -1;
}
   
static void read_all_keys(gnb_ctl_block_t *ctl_block) {
    char ip[16];
    inet_ntop(AF_INET, ctl_block->core_zone->log_ctx_st.addr4, ip, sizeof(ip));
    printf("core.flag=%u\n", ctl_block->core_zone->gnb_core_flag);
    printf("core.log.file.path=%s\n", ctl_block->conf_zone->conf_st.log_path);
    printf("core.log.file.std=%s\n", ctl_block->core_zone->log_ctx_st.log_file_name_std);
    printf("core.log.file.debug=%s\n", ctl_block->core_zone->log_ctx_st.log_file_name_debug);
    printf("core.log.file.error=%s\n", ctl_block->core_zone->log_ctx_st.log_file_name_error);
    printf("core.log.udp_addr4=%s\n", ip);
    printf("core.log.udp_port4=%u\n", ntohs(ctl_block->core_zone->log_ctx_st.port4));
    printf("core.log.udp_type=%u\n", ctl_block->conf_zone->conf_st.log_udp_type);
    print_log_level("core.log.console_level", ctl_block->conf_zone->conf_st.console_log_level);
    print_log_level("core.log.file_level", ctl_block->conf_zone->conf_st.file_log_level);
    print_log_level("core.log.udp_level", ctl_block->conf_zone->conf_st.udp_log_level);
    print_log_level("core.log.core_log_level", ctl_block->conf_zone->conf_st.core_log_level);
    print_log_level("core.log.pf_log_level", ctl_block->conf_zone->conf_st.pf_log_level);
    print_log_level("core.log.main_log_level", ctl_block->conf_zone->conf_st.main_log_level);
    print_log_level("core.log.node_log_level", ctl_block->conf_zone->conf_st.node_log_level);
    print_log_level("core.log.index_log_level", ctl_block->conf_zone->conf_st.index_log_level);
    print_log_level("core.log.index_service_log_level", ctl_block->conf_zone->conf_st.index_service_log_level);
    print_log_level("core.log.node_detect_log_level", ctl_block->conf_zone->conf_st.detect_log_level);
    printf("core.log.verbose=%s\n", GNB_SWITCH_STR(ctl_block->conf_zone->conf_st.log_verbose));
    printf("core.log.trace=%s\n", GNB_SWITCH_STR(ctl_block->conf_zone->conf_st.log_trace));
    printf("core.log.ifdump=%s\n", GNB_SWITCH_STR(ctl_block->conf_zone->conf_st.if_dump));
}

void gnb_ctl_core_read(gnb_ctl_block_t *ctl_block, gnb_arg_list_t *core_read_arg_list) {
    int i;
    for ( i=0; i < core_read_arg_list->argc; i++ ) {
        if ( !strcasecmp("all", core_read_arg_list->argv[i]) ) {
            read_all_keys(ctl_block);
            continue;
        }
        if ( read_single_key(ctl_block, core_read_arg_list->argv[i]) != 0 ) {
            printf("unknown key: %s\n", core_read_arg_list->argv[i]);
        }
    }
}
