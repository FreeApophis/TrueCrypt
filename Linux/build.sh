#!/bin/sh 
# TrueCrypt build script

KERNEL_SRC=/usr/src/linux-$(uname -r)

umask 022

error ()
{
	echo "Error: $*" >&2
}

check_kernel_version ()
{
	M="$1/Makefile"
	VER=$(grep '^VERSION *=' "$M" | head -n 1 | tr -d ' ' | cut -d'=' -f2)
	VER=$VER.$(grep '^PATCHLEVEL *=' "$M" | head -n 1 | tr -d ' ' | cut -d'=' -f2)
	VER=$VER.$(grep '^SUBLEVEL *=' "$M" | head -n 1 | tr -d ' ' | cut -d'=' -f2)

	[ $VER = $( uname -r | tr -- - . | cut -d. -f1-3) ] && return 0
	return 1
}

# Prerequisites

echo "Checking build requirements..."

[ $(id -u) -ne 0 ] && error "Administrator (root) privileges required" && exit 1

V=""
case "$(uname -r)" in
	[01].*) V=1 ;;
	2.[0-5].*) V=1 ;;
	2.6.[0-4]) V=1 ;;
	2.6.[0-4][.-]*) V=1 ;;
esac
[ "$V" ] && error "TrueCrypt requires Linux kernel 2.6.5 or later" && exit 1

[ ! -d $KERNEL_SRC ] && KERNEL_SRC=/usr/src/linux
if [ ! -d $KERNEL_SRC ] || ! check_kernel_version "$KERNEL_SRC"
then
	echo -n "Linux kernel ($(uname -r)) source directory [$KERNEL_SRC]: "
	read A
	[ "$A" ] && KERNEL_SRC="$A"
	[ ! -d $KERNEL_SRC ] && error "$KERNEL_SRC does not exit" && exit 1
fi 

if ! check_kernel_version "$KERNEL_SRC"
then
	error "Kernel source version in $KERNEL_SRC is not $(uname -r)"
	exit 1
fi

if [ ! -f "$KERNEL_SRC/.config" ]
then
	error "Kernel not configured. You should run make -C $KERNEL_SRC config modules"
	exit 1
fi

if [ ! -f "$KERNEL_SRC/drivers/md/dm.h" ]
then
	error "Kernel source code is incomplete - header file dm.h not found."
	exit 1
fi

grep -qi 'CONFIG_BLK_DEV_DM=N' $KERNEL_SRC/.config && echo "Warning: kernel device mapper support (CONFIG_BLK_DEV_DM) is disabled in $KERNEL_SRC" && sleep 5


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
