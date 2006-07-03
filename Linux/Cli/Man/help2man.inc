[NAME]
truecrypt - manage TrueCrypt volumes
[DIAGNOSTICS]
Exit status
.B 0
is returned if all requested actions completed successfully, otherwise
.B 1
is returned. Kernel module reports errors via system log with facility
.BR "kern" ". See"
.BR "syslogd" "(8) for more information."
[SEE ALSO]
.B http://www.truecrypt.org/docs/
.br
.B /usr/share/truecrypt/doc/TrueCrypt-User-Guide.pdf
.br
.BR "mount" "(8), " "umount" "(8), " "losetup" "(8), "
.BR "fuser" "(1), " "mkfs" "(8), " "fsck" "(8), " "dmsetup" "(8)"
