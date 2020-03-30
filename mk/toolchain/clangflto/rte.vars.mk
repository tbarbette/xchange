# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

#
# toolchain:
#
#   - define CC, LD, AR, AS, ... (overridden by cmdline value)
#   - define TOOLCHAIN_CFLAGS variable (overridden by cmdline value)
#   - define TOOLCHAIN_LDFLAGS variable (overridden by cmdline value)
#   - define TOOLCHAIN_ASFLAGS variable (overridden by cmdline value)
#

CC        = $(CROSS)clang -flto
KERNELCC  = $(CROSS)gcc
CPP       = $(CROSS)cpp
# for now, we don't use as but nasm.
# AS      = $(CROSS)as
AS        = nasm
AR        = $(CROSS)llvm-ar
LD        = $(CROSS)ld.lld
OBJCOPY   = $(CROSS)llvm-objcopy
OBJDUMP   = $(CROSS)llvm-objdump
STRIP     = $(CROSS)llvm-strip
READELF   = $(CROSS)llvm-readelf
GCOV      = $(CROSS)llvm-cov
RANLIB    = $(CROSS)llvm-ranlib
LLC       = $(CROSS)llc -filetype=obj


ifeq ("$(origin CC)", "command line")
HOSTCC    = $(CC)
else
HOSTCC    = clang
endif
HOSTAS    = as

TOOLCHAIN_ASFLAGS =
TOOLCHAIN_CFLAGS = 
TOOLCHAIN_LDFLAGS = -plugin-opt=save-temps

WERROR_FLAGS := -W -Wall -Wstrict-prototypes -Wmissing-prototypes
WERROR_FLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith
WERROR_FLAGS += -Wnested-externs -Wcast-qual
WERROR_FLAGS += -Wformat-nonliteral -Wformat-security
WERROR_FLAGS += -Wundef -Wwrite-strings -Wdeprecated

ifeq ($(RTE_DEVEL_BUILD),y)
WERROR_FLAGS += -Werror
endif

# process cpu flags
include $(RTE_SDK)/mk/toolchain/$(RTE_TOOLCHAIN)/rte.toolchain-compat.mk

# disable warning for non-initialised fields
WERROR_FLAGS += -Wno-missing-field-initializers

# disable packed member unalign warnings
ifeq ($(shell test $(CLANG_MAJOR_VERSION) -ge 4 && echo 1), 1)
WERROR_FLAGS += -Wno-address-of-packed-member
endif

export CC AS AR LD OBJCOPY OBJDUMP STRIP READELF RANLIB LLC
export TOOLCHAIN_CFLAGS TOOLCHAIN_LDFLAGS TOOLCHAIN_ASFLAGS
