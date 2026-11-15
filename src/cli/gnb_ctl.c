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
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include "gnb_conf_type.h"
#include "gnb_alloc.h"
#include "gnb_ctl_block.h"
#include "gnb_arg_list.h"
#include "gnb_version.h"

void gnb_ctl_dump_status(gnb_ctl_block_t *ctl_block, gnb_uuid_t in_nodeid, uint8_t online_opt, uint8_t addr_secure);
void gnb_ctl_dump_address_list(gnb_ctl_block_t *ctl_block, gnb_uuid_t in_nodeid, uint8_t online_opt, int address_type, uint8_t format, uint8_t addr_secure);
void gnb_ctl_core_write(gnb_ctl_block_t *ctl_block, gnb_arg_list_t *core_rw_arg_list);
void gnb_ctl_core_read(gnb_ctl_block_t *ctl_block, gnb_arg_list_t *core_read_arg_list);
void gnb_ctl_core_restart(gnb_ctl_block_t *ctl_block);

#define GNB_OPT_INIT                   0x91
#define SET_ADDR_SECURE                (GNB_OPT_INIT + 1)
#define SET_RESTART                    (GNB_OPT_INIT + 2)

static void show_useage(int argc,char *argv[]) {
    printf("GNB Ctl\n");
    printf("%s\n", GNB_VERSION_STRING);
    printf("%s\n", GNB_BUILD_STRING);

    printf("Copyright (C) 2019 gnbdev\n");
    printf("Usage: %s -b CTL_BLOCK [OPTION]\n", argv[0]);
    printf("Command Summary:\n");

    printf("  -b, --ctl-block           ctl block mapper file\n");
    printf("  -s, --status              dunmp node status\n");
    printf("  -o, --online              dunmp online node\n");
    printf("  -a, --address             dunmp address 0:foramt0,1:foramt1 defalt:0\n");

    printf("  -4, --ipv4-only           Use IPv4 Only\n");
    printf("  -6, --ipv6-only           Use IPv6 Only\n");
    printf("  -n, --node                node id\n");
    printf("      --address-secure      hide part of ip address in logs \"on\",\"off\" default:\"on\"\n");
    printf("  -w, --write               write ctl block share memory\n");
    printf("  -r, --read                read ctl block data ('all' for all items)\n");
    printf("  -R, --restart             restart gnb core\n");
    printf("      --help\n");

    printf("\nWrite/Read Keys:\n");
    printf("  core.flag=2|restart              restart gnb core\n");
    printf("  core.log.file.path=PATH          set log directory\n");
    printf("  core.log.file.std=FILE           set std log file path\n");
    printf("  core.log.file.debug=FILE         set debug log file path\n");
    printf("  core.log.file.error=FILE         set error log file path\n");
    printf("  core.log.file.rotate=1           force trigger log rotate (write only)\n");
    printf("  core.log.udp_addr4=IP            set udp log ipv4 address\n");
    printf("  core.log.udp_port4=PORT          set udp log port\n");
    printf("  core.log.udp_type=0|1            set udp log type 0:text 1:binary\n");
    printf("  core.log.console_level=LEVEL     set console log level (0-5 or unset)\n");
    printf("  core.log.file_level=LEVEL        set file log level (0-5 or unset)\n");
    printf("  core.log.udp_level=LEVEL         set udp log level (0-5 or unset)\n");
    printf("  core.log.core_log_level=LEVEL    set core log level (0-5 or unset)\n");
    printf("  core.log.pf_log_level=LEVEL      set pf log level (0-5 or unset)\n");
    printf("  core.log.main_log_level=LEVEL    set main worker log level (0-5 or unset)\n");
    printf("  core.log.node_log_level=LEVEL    set node worker log level (0-5 or unset)\n");
    printf("  core.log.index_log_level=LEVEL   set index worker log level (0-5 or unset)\n");
    printf("  core.log.index_service_log_level=LEVEL set index service log level (0-5 or unset)\n");
    printf("  core.log.node_detect_log_level=LEVEL   set detect worker log level (0-5 or unset)\n");
    printf("  core.log.verbose=on|off          set verbose mode (-V, also supports 1|0)\n");
    printf("  core.log.trace=on|off            set trace mode (-T, also supports 1|0)\n");
    printf("  core.log.ifdump=on|off           set interface dump (--if-dump, also supports 1|0)\n");

    printf("\nexample:\n");
    printf("  %s -b gnb.map -s\n", argv[0]);
    printf("  %s -b gnb.map -r all\n", argv[0]);
    printf("  %s -b gnb.map -r core.log.console_level\n", argv[0]);
    printf("  %s -b gnb.map --restart\n", argv[0]);
    printf("  %s -b gnb.map -w core.flag=restart\n", argv[0]);
    printf("  %s -b gnb.map -w core.log.verbose=on\n", argv[0]);
    printf("  %s -b gnb.map -w core.log.file.rotate=1\n", argv[0]);
}

int main (int argc,char *argv[]) {
    int r;
    char *ctl_block_file = NULL;
    uint8_t  address_opt      = 0;
    uint8_t  address_type     = 0x3;  // bit0=1:IPV4, bit1=1:IPV6
    uint8_t  write_opt        = 0;
    uint8_t  read_opt         = 0;
    uint8_t  restart_opt      = 0;
    uint8_t  node_status_opt  = 0;
    uint8_t  online_opt       = 0;
    uint8_t  address_format   = 0;
    uint8_t addr_secure = 0;
    gnb_uuid_t nodeid = 0;
    gnb_arg_list_t *core_rw_arg_list;
    gnb_arg_list_t *core_read_arg_list;
    gnb_heap_t *heap = gnb_heap_create(8192);
    gnb_ctl_block_t *ctl_block = (gnb_ctl_block_t *)gnb_heap_alloc(heap, sizeof(gnb_ctl_block_t));
    ctl_block->mmap_block = (gnb_mmap_block_t *)gnb_heap_alloc(heap, sizeof(gnb_mmap_block_t));
    core_rw_arg_list   = gnb_arg_list_init(heap, 1024);
    core_read_arg_list = gnb_arg_list_init(heap, 1024);

    static struct option long_options[] = {
      { "ctl-block",            required_argument,  0, 'b' },
      { "node",                 required_argument,  0, 'n' },
      { "status",               no_argument,        0, 's' },
      { "address",              required_argument,  0, 'a' },
      { "online",               no_argument,        0, 'o' },
      { "address-secure",       required_argument,  0, SET_ADDR_SECURE },
      { "ipv4-only",            no_argument,        0, '4' },
      { "ipv6-only",            no_argument,        0, '6' },
      { "write",                required_argument,  0, 'w' },
      { "read",                 required_argument,  0, 'r' },
      { "restart",              no_argument,        0, SET_RESTART },
      { "help",                 no_argument,        0, 'h' },
      { 0, 0, 0, 0 }
    };

    setvbuf(stdout,NULL,_IOLBF,0);
    int opt;
    while (1) {
        int option_index = 0;
        opt = getopt_long (argc, argv, "b:n:csa:o46w:r:hR", long_options, &option_index);
        if ( opt == -1 ) {
            break;
        }
        switch (opt) {
        case 'b':
            ctl_block_file = optarg;
            break;
        case 'n':
            nodeid = (gnb_uuid_t)strtoull(optarg, NULL, 10);
            break;
        case 's':
            node_status_opt = 1;
            break;
        case 'a':
            address_opt = 1;
            address_format = (uint8_t)strtoull(optarg, NULL, 10);
            break;
        case 'o':
            online_opt = 1;
            break;
        case '6':
            address_type = 0x2;
            break;
        case '4':
            address_type = 0x1;
            break;
        case SET_ADDR_SECURE:
            if ( !strncmp(optarg, "on", 2) ) {
                addr_secure = 1;
            } else if ( !strncmp(optarg, "off", 3) ) {
                addr_secure = 0;
            } else {
                addr_secure = 1;
            }
            break;
        case 'w':
            gnb_arg_append(core_rw_arg_list, optarg);
            write_opt = 1;
            break;
        case 'r':
            gnb_arg_append(core_read_arg_list, optarg);
            read_opt = 1;
            break;
        case 'R':
        case SET_RESTART:
            restart_opt = 1;
            break;
        case 'h':
            show_useage(argc,argv);
            exit(0);
        default:
            break;
        }
    }
    if ( NULL == ctl_block_file ) {
        show_useage(argc,argv);
        exit(0);
    }
    r = gnb_get_ctl_block(ctl_block, ctl_block_file, 0);
    if ( 0 != r ) {
        printf("open ctl block error [%s]\n",ctl_block_file);
        exit(0);
    }

#ifdef _WIN32
    WSADATA wsaData;
    int err;
    err = WSAStartup(MAKEWORD(2, 2), &wsaData );
#endif

    if ( node_status_opt ) {
        gnb_ctl_dump_status(ctl_block, nodeid, online_opt, addr_secure);
    }
    if ( address_opt ) {
        if ( 0 != address_format && 1 != address_format ) {
            address_format = 0;
        }
        if ( 1 == address_format ) {
            addr_secure = 0;
        }
        gnb_ctl_dump_address_list(ctl_block, nodeid, online_opt, address_type, address_format, addr_secure);
    }
    if ( write_opt ) {
        gnb_ctl_core_write(ctl_block, core_rw_arg_list);
    }
    if ( read_opt ) {
        gnb_ctl_core_read(ctl_block, core_read_arg_list);
    }
    if ( restart_opt ) {
        gnb_ctl_core_restart(ctl_block);
    }
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
