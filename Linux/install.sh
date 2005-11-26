#!/bin/sh 
# TrueCrypt install script

BIN_DIR=/usr/local/bin
MAN_DIR=/usr/local/man
MOD_DIR=/lib/modules/$(uname -r)/extra
BIN_PERM=755

umask 022

error ()
{
	echo "Error: $*" >&2
}

# Prerequisites

echo "Checking installation requirements..."

[ $(id -u) -ne 0 ] && error "Administrator (root) privileges required" && exit 1

if ! modprobe -V >&- 2>&- || ! rmmod -V >&- 2>&-
then
	error "modprobe or rmmod not found. TrueCrypt requires kernel module tools."
	exit 1
fi

if [ ! -c /dev/mapper/control -a ! -L /dev/mapper/control ]
then
	echo -n "/dev/mapper/control not found - create? [Y/n]: "
	read A
	if [ "$A" = "" -o "$A" = "y" -o "$A" = "Y" ]
	then
		mkdir /dev/mapper 2>/dev/null && chmod 755 /dev/mapper
		mknod -m 600 /dev/mapper/control c 10 63
	fi
fi

modprobe dm-mod >&- 2>&-

if ! dmsetup targets >&- 2>&-
then
	error "TrueCrypt requires device mapper tools (dmsetup) 1.00.08 or later."
	exit 1
fi

if [ ! -b /dev/loop0 -a ! -b /dev/loop/0 -a ! -b /dev/loop1 ]
then
	echo -n "No loopback device found - create? [Y/n]: "
	read A
	if [ "$A" = "y" -o "$A" = "Y" ]
	then
		for I in 0 1 2 3 4 5 6 7
		do
			mknod -m 600 /dev/loop$I b 7 $I
		done
	fi
fi

rmmod truecrypt >&- 2>&-
if grep -q "^truecrypt " /proc/modules
then
	error "Please dismount all mounted TrueCrypt volumes first."
	exit 1
fi


# Build

if [ ! -f Kernel/truecrypt.ko -o ! -f Cli/truecrypt ]
then
	./build.sh
	[ $? -ne -0 ] && error "Build failed - installation aborted" && exit 1
fi


# Test

echo -n "Testing truecrypt... "
./Cli/truecrypt --test >/dev/null 2>/dev/null
[ $? -ne 0 ] && echo "FAILED" && exit 1
echo Done.


# Installation

echo
echo -n "Install binaries to [$BIN_DIR]: "
read A
[ "$A" ] && BIN_DIR=$A
[ ! -d $BIN_DIR ] && error "$BIN_DIR does not exist" && exit 1

echo -n "Install man page to [$MAN_DIR]: "
read A
[ "$A" ] && MAN_DIR=$A
[ ! -d $MAN_DIR/man1 ] && error "$MAN_DIR/man1 does not exist" && exit 1
MAN_DIR=$MAN_DIR/man1

echo -n "Allow non-admin users to run TrueCrypt [y/N]: "
read A
[ "$A" = "y" ] && BIN_PERM=4755

echo -n "Installing kernel module... "
# make "KERNEL_SRC=$KERNEL_SRC" install >/dev/null
mkdir $MOD_DIR 2>&-  # some distributions omit extra directory
cp Kernel/truecrypt.ko $MOD_DIR && chmod 600 $MOD_DIR/truecrypt.ko && depmod -a
[ $? -ne 0 ] && error "Failed to install kernel module" && exit 1
echo Done.

echo -n "Installing truecrypt to $BIN_DIR... "
cp Cli/truecrypt "$BIN_DIR" && chown root:root "$BIN_DIR/truecrypt" && chmod $BIN_PERM "$BIN_DIR/truecrypt"
[ $? -ne 0 ] && error "Failed to install truecrypt" && exit 1
echo Done.

echo -n "Installing truecrypt man page to $MAN_DIR... "
cp Cli/Man/truecrypt.1 "$MAN_DIR" && chown root:root "$MAN_DIR/truecrypt.1" && chmod 644 "$MAN_DIR/truecrypt.1"
[ $? -ne 0 ] && error "Failed to install truecrypt man page" && exit 1
echo Done.

exit 0
