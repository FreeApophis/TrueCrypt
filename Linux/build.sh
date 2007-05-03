#!/bin/bash 
#
# Copyright (c) TrueCrypt Foundation. All rights reserved.
#
# Covered by the TrueCrypt License 2.3 the full text of which is contained
# in the file License.txt included in TrueCrypt binary and source code
# distribution packages.
#

[ -z "$KERNEL_VER" ] && KERNEL_VER=$(uname -r)
KERNEL_BUILD=/lib/modules/$KERNEL_VER/build
KERNEL_SRC=/lib/modules/$KERNEL_VER/source

TMP=.build.sh.tmp
umask 022

error ()
{
	echo "Error: $*" >&2
}

check_kernel_version ()
{
	M="$1/Makefile"
	[ ! -f "$M" ] && return 1
	
	VER=$(grep '^VERSION *=' "$M" | head -n 1 | tr -d ' ' | cut -d'=' -f2)
	VER=$VER.$(grep '^PATCHLEVEL *=' "$M" | head -n 1 | tr -d ' ' | cut -d'=' -f2)
	VER=$VER.$(grep '^SUBLEVEL *=' "$M" | head -n 1 | tr -d ' ' | cut -d'=' -f2)

	[ $VER = $(echo $KERNEL_VER | cut -d- -f1 | cut -d. -f1-3) ] && return 0
	return 1
}

# Prerequisites

echo "Checking build requirements..."

[ $(id -u) -ne 0 ] && error "Administrator (root) privileges required for kernel source configuration." && exit 1

V=""
case "$KERNEL_VER" in
	[01].*) V=1 ;;
	2.[0-5].*) V=1 ;;
	2.6.[0-4]) V=1 ;;
	2.6.[0-4][.-]*) V=1 ;;
esac
[ "$V" ] && error "TrueCrypt requires Linux kernel 2.6.5 or later" && exit 1

check_kernel_version "$KERNEL_SRC" || KERNEL_SRC=/usr/src/linux-$KERNEL_VER
check_kernel_version "$KERNEL_SRC" || KERNEL_SRC=/usr/src/linux-source-$KERNEL_VER
check_kernel_version "$KERNEL_SRC" || KERNEL_SRC=/usr/src/kernels/$KERNEL_VER-$(uname -p)
check_kernel_version "$KERNEL_SRC" || KERNEL_SRC=/usr/src/linux-$(echo $KERNEL_VER | cut -d'-' -f1)
check_kernel_version "$KERNEL_SRC" || KERNEL_SRC=/usr/src/linux-source-$(echo $KERNEL_VER | cut -d'-' -f1)
check_kernel_version "$KERNEL_SRC" || KERNEL_SRC=/usr/src/linux

if ! check_kernel_version "$KERNEL_SRC"
then
	echo -n "Linux kernel ($KERNEL_VER) source directory [$KERNEL_SRC]: "
	read A
	[ "$A" ] && KERNEL_SRC="$A"
	[ ! -d "$KERNEL_SRC" ] && error "$KERNEL_SRC does not exit" && exit 1
fi 

if ! check_kernel_version "$KERNEL_SRC"
then
	error "Kernel source version in $KERNEL_SRC is not $KERNEL_VER"
	exit 1
fi

if [ ! -f "$KERNEL_SRC/drivers/md/dm.h" ]
then
	error "Kernel source code is incomplete - $KERNEL_SRC/drivers/md/dm.h not found."
	exit 1
fi

if [ ! -d "$KERNEL_BUILD/include/asm/" -o ! -f "$KERNEL_BUILD/Module.symvers" -o ! -f "$KERNEL_BUILD/.config" ]
then
	if [ ! -f "$KERNEL_SRC/.config" ]
	then
		if [ -f /proc/config.gz -o -f /boot/config-$KERNEL_VER -o -f /boot/config-$(uname -r) ]
		then
			echo -n "Configure kernel source according to the system configuration? [Y/n]: "
			read A
			if [ -z "$A" -o "$A" = "y" -o "$A" = "Y" ]
			then
				echo -n "Configuring kernel source in $KERNEL_SRC... "
				
				if [ -f /proc/config.gz ]
				then
					zcat /proc/config.gz >$KERNEL_SRC/.config || exit 1
				else
					if [ -f /boot/config-$(uname -r) ]
					then
						cp /boot/config-$(uname -r) $KERNEL_SRC/.config || exit 1
					else
						cp /boot/config-$KERNEL_VER $KERNEL_SRC/.config || exit 1
					fi
				fi
				
				make -C $KERNEL_SRC oldconfig </dev/null >/dev/null || exit 1
				echo Done.
			fi
		fi

		if [ ! -f "$KERNEL_SRC/.config" ]
		then
			error "Kernel not configured. You should run make -C $KERNEL_SRC config"
			exit 1
		fi
	fi

	if [ ! -d "$KERNEL_SRC/include/asm" ] && grep -q modules_prepare $KERNEL_SRC/Makefile
	then
		echo -n "Preparing kernel build system in $KERNEL_SRC... "
		if ! make -C $KERNEL_SRC modules_prepare >/dev/null 2>$TMP
		then
			cat $TMP; rm $TMP
			exit 1
		fi
		rm $TMP
		echo Done.
	fi


	if [ ! -d "$KERNEL_SRC/include/asm" -o ! -f "$KERNEL_SRC/Module.symvers" ] 
	then
		echo -n "Building internal kernel modules (may take a long time)... "
		if ! make -C $KERNEL_SRC modules >/dev/null 2>$TMP
		then
			cat $TMP; rm $TMP
			exit 1
		fi
		rm $TMP
		echo Done.
	fi

	if [ ! -d "$KERNEL_SRC/include/asm" ]
	then
		error "Kernel source code is not prepared for building of modules - $KERNEL_SRC/include/asm not found."
		exit 1
	fi
	
	KERNEL_BUILD=$KERNEL_SRC
fi

if [ -f $KERNEL_BUILD/.config ]
then
	grep -qi 'CONFIG_BLK_DEV_DM=[YM]' $KERNEL_BUILD/.config || echo "Warning: kernel device mapper support (CONFIG_BLK_DEV_DM) is disabled in $KERNEL_SRC"
fi

# Build

echo -n "Building kernel module... "
cd Kernel && make "KERNEL_SRC=$KERNEL_SRC" "KERNEL_BUILD=$KERNEL_BUILD" NO_WARNINGS=1 >/dev/null
[ $? -ne 0 ] && error "Failed to build kernel module" && exit 1
echo Done.

echo -n "Building truecrypt... "
cd ../Cli && make NO_WARNINGS=1 >/dev/null
[ $? -ne 0 ] && error "Failed to build truecrypt" && exit 1
echo Done.

exit 0
