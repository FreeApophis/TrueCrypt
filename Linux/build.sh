#!/bin/sh 
# TrueCrypt build script

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

	[ $VER = $(uname -r | cut -d- -f1 | cut -d. -f1-3) ] && return 0
	return 1
}

# Prerequisites

echo "Checking build requirements..."

[ $(id -u) -ne 0 ] && error "Administrator (root) privileges required for kernel source configuration." && exit 1

V=""
case "$(uname -r)" in
	[01].*) V=1 ;;
	2.[0-5].*) V=1 ;;
	2.6.[0-4]) V=1 ;;
	2.6.[0-4][.-]*) V=1 ;;
esac
[ "$V" ] && error "TrueCrypt requires Linux kernel 2.6.5 or later" && exit 1

KERNEL_SRC=/usr/src/linux-source-$(uname -r)
check_kernel_version "$KERNEL_SRC" || KERNEL_SRC=/usr/src/linux-source-$(uname -r | cut -d'-' -f1)
check_kernel_version "$KERNEL_SRC" || KERNEL_SRC=/usr/src/linux-$(uname -r)
check_kernel_version "$KERNEL_SRC" || KERNEL_SRC=/usr/src/linux-$(uname -r | cut -d'-' -f1)
check_kernel_version "$KERNEL_SRC" || KERNEL_SRC=/usr/src/linux

if ! check_kernel_version "$KERNEL_SRC"
then
	echo -n "Linux kernel ($(uname -r)) source directory [$KERNEL_SRC]: "
	read A
	[ "$A" ] && KERNEL_SRC="$A"
	[ ! -d "$KERNEL_SRC" ] && error "$KERNEL_SRC does not exit" && exit 1
fi 

if ! check_kernel_version "$KERNEL_SRC"
then
	error "Kernel source version in $KERNEL_SRC is not $(uname -r)"
	exit 1
fi

if [ ! -f "$KERNEL_SRC/drivers/md/dm.h" ]
then
	error "Kernel source code is incomplete - drivers/md/dm.h not found."
	exit 1
fi

if [ ! -f "$KERNEL_SRC/.config" ]
then
	if [ -f /proc/config.gz -o -f /boot/config-$(uname -r) ]
	then
		echo -n "Configure kernel source according to the currently running kernel? [Y/n]: "
		read A
		if [ -z "$A" -o "$A" = "y" -o "$A" = "Y" ]
		then
			echo -n "Configuring kernel source in $KERNEL_SRC... "
			
			if [ -f /proc/config.gz ]
			then
				zcat /proc/config.gz >$KERNEL_SRC/.config || exit 1
			else
				cp /boot/config-$(uname -r) $KERNEL_SRC/.config || exit 1
			fi
			
			make -C $KERNEL_SRC oldconfig </dev/zero >/dev/null || exit 1
			echo Done.
		fi
	fi

	if [ ! -f "$KERNEL_SRC/.config" ]
	then
		error "Kernel not configured. You should run make -C $KERNEL_SRC config"
		exit 1
	fi
fi

if [ ! -f "$KERNEL_SRC/scripts/modpost" -a ! -f "$KERNEL_SRC/scripts/mod/modpost" ]
then
	if grep -q modules_prepare $KERNEL_SRC/Makefile
	then
		echo -n "Preparing kernel build system in $KERNEL_SRC... "
		if ! make -C $KERNEL_SRC modules_prepare >/dev/null 2>$TMP
		then
			cat $TMP; rm $TMP
			exit 1
		fi
		rm $TMP
		echo Done.
	else
		error "Kernel build system not ready. You should run make -C $KERNEL_SRC modules"
		exit 1
	fi
fi

grep -qi 'CONFIG_BLK_DEV_DM=[YM]' $KERNEL_SRC/.config || echo "Warning: kernel device mapper support (CONFIG_BLK_DEV_DM) is disabled in $KERNEL_SRC"

if [ ! -f "$KERNEL_SRC/Module.symvers" ] && grep -qi 'CONFIG_MODVERSIONS=Y' $KERNEL_SRC/.config 
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


# Build

echo -n "Building kernel module... "
cd Kernel && make "KERNEL_SRC=$KERNEL_SRC" NO_WARNINGS=1 >/dev/null
[ $? -ne 0 ] && error "Failed to build kernel module" && exit 1
echo Done.

echo -n "Building truecrypt... "
cd ../Cli && make NO_WARNINGS=1 >/dev/null
[ $? -ne 0 ] && error "Failed to build truecrypt" && exit 1
echo Done.

exit 0
