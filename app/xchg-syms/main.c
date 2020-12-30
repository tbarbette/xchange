/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <rte_string_fns.h>
#include <rte_ipsec_sad.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <rte_ethdev.h>
#include <rte_errno.h>

#define	PRINT_USAGE_START	"%s [EAL options] --\n"

struct config_t {
    char* prgname;
    int header;
};

struct config_t config;

static void
print_usage(void)
{
	fprintf(stdout,
		PRINT_USAGE_START
		"[-h help]\n",
		config.prgname);

}


static void
parse_opts(int argc, char **argv)
{
	int opt;
//    int ret;
//	char *endptr;

	while ((opt = getopt(argc, argv, "h")) != -1) {
		switch (opt) {
		case 'h':
			config.header = 1;
			break;
/*		case 't':
			config.tuples_file = optarg;
			break;
		case 'n':
			errno = 0;
			config.nb_rules = strtoul(optarg, &endptr, 10);
			if ((errno != 0) || (config.nb_rules == 0) ||
					(endptr[0] != 0)) {
				print_usage();
				rte_exit(-EINVAL, "Invalid option -n\n");
			}
			break;
		case 'd':
			ret = parse_distrib(optarg);
			if (ret != 0) {
				print_usage();
				rte_exit(-EINVAL, "Invalid option -d\n");
			}
			break;
		case 'b':
			errno = 0;
			config.burst_sz = strtoul(optarg, &endptr, 10);
			if ((errno != 0) || (config.burst_sz == 0) ||
					(config.burst_sz > BURST_SZ_MAX) ||
					(endptr[0] != 0)) {
				print_usage();
				rte_exit(-EINVAL, "Invalid option -b\n");
			}
			break;
		case 'l':
			errno = 0;
			config.nb_tuples = strtoul(optarg, &endptr, 10);
			if ((errno != 0) || (config.nb_tuples == 0) ||
					(endptr[0] != 0)) {
				print_usage();
				rte_exit(-EINVAL, "Invalid option -l\n");
			}
			break;
		case 'r':
			errno = 0;
			config.fract_rnd_tuples = strtoul(optarg, &endptr, 10);
			if ((errno != 0) || (config.fract_rnd_tuples == 0) ||
					(config.fract_rnd_tuples >= 100) ||
					(endptr[0] != 0)) {
				print_usage();
				rte_exit(-EINVAL, "Invalid option -r\n");
			}
			break;
		case '6':
			config.ipv6 = 1;
			break;
		case 'v':
			config.verbose = 1;
			break;
		case 'p':
			config.parallel_lookup = 1;
			break;
		case 'c':
			config.concurrent_rw = 1;
			break;*/
		default:
			print_usage();
			rte_exit(-EINVAL, "Invalid options\n");
		}
	}
}

void get_sym(char* buf, void* ptr);
void get_sym(char* buf, void* ptr) {
    sprintf(buf, "llvm-symbolizer --obj=%s %p",config.prgname, ptr);

	FILE *fp = popen(buf, "r");
	fscanf(fp, "%s", buf);
	pclose(fp);
}

int
main(int argc, char **argv)
{
	int ret;
//	unsigned int lcore_id;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	argc -= ret;
	argv += ret;

	config.prgname = argv[0];

	parse_opts(argc, argv);

    char buf[256];
    char buftx[256];
    rte_eth_dev_start(0);
	struct rte_eth_dev *dev = &rte_eth_devices[0];

    get_sym(buf,dev->rx_pkt_burst_xchg);

    get_sym(buftx,dev->rx_pkt_burst_xchg);

    FILE * fh = fopen("rte_direct.h", "w");
    if (config.header) {
        fprintf(fh, "#define RTE_DIRECT 1\n");
        fprintf(fh,"int %s(void*,struct xchg**, uint16_t);\n", buf);
        fprintf(fh,"static __rte_always_inline uint16_t\n"
"rte_direct_rx_burst_xchg(uint16_t port_id, uint16_t queue_id,"
"                         struct xchg **xchgs, const uint16_t nb_pkts)"
"            {"
"                 struct rte_eth_dev *dev = &rte_eth_devices[port_id];"
"                 uint16_t nb_rx;"
"                 nb_rx = %s(dev->data->rx_queues[queue_id],"
"                            xchgs, nb_pkts);"
"                 return nb_rx;"
"            };\n", buf);
        fprintf(fh,"int %s(void*,struct xchg**, uint16_t);\n", buftx);
        fprintf(fh,"static __rte_always_inline uint16_t\n"
"rte_direct_tx_burst_xchg(uint16_t port_id, uint16_t queue_id,"
"                         struct xchg **xchgs, const uint16_t nb_pkts)"
"            {"
"                 struct rte_eth_dev *dev = &rte_eth_devices[port_id];"
"                 uint16_t nb_tx;"
"                 nb_tx = %s(dev->data->tx_queues[queue_id],"
"                            xchgs, nb_pkts);"
"                 return nb_tx;"
"            };\n", buftx);
    } else {
        printf("%s", buf);
    }
    fclose(fh);

	return 0;
}
