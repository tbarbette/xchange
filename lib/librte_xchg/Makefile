# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = librte_xchg_mbuf.a

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR) -O3 -fno-strict-aliasing

# EXPORT_MAP := rte_power_version.map

# all source are stored in SRCS-y
SRCS-$(CONFIG_RTE_LIBRTE_XCHG_MBUF) := rte_xchg_mbuf.c

# install this header file
SYMLINK-$(CONFIG_RTE_LIBRTE_XCHG)-include := rte_xchg.h

include $(RTE_SDK)/mk/rte.lib.mk
