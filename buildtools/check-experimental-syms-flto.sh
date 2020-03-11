#!/bin/sh

# SPDX-License-Identifier: BSD-3-Clause

MAPFILE=$1
OBJFILE=$2

LIST_SYMBOL=$(dirname $(readlink -f $0))/map-list-symbol.sh

# added check for "make -C test/" usage
if [ ! -e $MAPFILE ] || [ ! -f $OBJFILE ]
then
	exit 0
fi

if [ -d $MAPFILE ]
then
	exit 0
fi

DUMPFILE=$(mktemp -t dpdk.${0##*/}.XXX.objdump)
trap 'rm -f "$DUMPFILE"' EXIT
#llvm-objdump -t $OBJFILE 1>/dev/null 2> $DUMPFILE"-error"
#error=`grep -c 'The file was not recognized as a valid object file'  $DUMPFILE"-error"`
#echo "error is $error"
#rm -f  $DUMPFILE"-error"
#if [ $error -eq 1 ]; then
#	objdump -t $OBJFILE >$DUMPFILE
#else
#	llvm-objdump -t $OBJFILE >$DUMPFILE
#fi

ret=0
for SYM in `$LIST_SYMBOL -S EXPERIMENTAL $MAPFILE |cut -d ' ' -f 3`
do
	if grep -q "\.text.*[[:space:]]$SYM$" $DUMPFILE &&
		! grep -q "\.text\.experimental.*[[:space:]]$SYM$" $DUMPFILE
	then
		cat >&2 <<- END_OF_MESSAGE
		$SYM is not flagged as experimental
		but is listed in version map
		Please add __rte_experimental to the definition of $SYM
		END_OF_MESSAGE
		ret=1
	fi
done

# Filter out symbols suffixed with a . for icc
for SYM in `awk '{
	if ($2 != "l" && $4 == ".text.experimental" && !($NF ~ /\.$/)) {
		print $NF
	}
}' $DUMPFILE`
do
	$LIST_SYMBOL -S EXPERIMENTAL -s $SYM -q $MAPFILE || {
		cat >&2 <<- END_OF_MESSAGE
		$SYM is flagged as experimental
		but is not listed in version map
		Please add $SYM to the version map
		END_OF_MESSAGE
		ret=1
	}
done

exit $ret
