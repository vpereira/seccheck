#!/bin/sh
####
#
# SuSE weekly security check v2.0 by Marc Heuse <marc@suse.de>
#
####
#
# TODO /etc /home /home/.* permissions
#

. /etc/sysconfig/seccheck

. basic.inc

source helper.inc

set_tmpdir $0

trap 'rm -rf $TMPDIR; exit 1' 0 1 2 3 13 15

OUT="$TMPDIR/security.out"
TMP1="$TMPDIR/security.tmp1"
TMP2="$TMPDIR/security.tmp2"

create_secdir

# initialize rmp-md5, sbit, write, device and write-bin
initialize_secfiles $SEC_DATA

# get the ext2 and reiserfs mount points
MNT=`/bin/mount | grep -E "^/dev/"  | cut -d' ' -f 3 | grep -v "/media" | xargs  echo "/dev/"`

set_mailer

# extended password check
check_guessable_passwords "extended"

# neverlogin check
check_neverlogin $SEC_BIN $OUT

check_suid_gid $MNT

check_writable_executable $MNT

check world_writable $MNT

check_new_devices $MNT


####
#
# Cleaning up
#
rm -rf "$TMPDIR"
exit 0
# END OF SCRIPT
