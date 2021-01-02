#!/bin/bash
echo "Give DPDK arguments such as '-w 0000:11:00.0,rx_vec_en=1,rxq_cqe_comp_en=0,mprq_en=0' to select a device and run-time parameters"
echo "Looking for the right symbol..."
sudo $(pwd)/../$RTE_TARGET/app/dpdksyms $@ -- -h
echo "Recompiling with symbols..."
make EXTRA_CFLAGS="-include $(pwd)/rte_direct.h"
