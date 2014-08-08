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

. ./basic.inc

source helper.inc

set_tmpdir $0

trap 'rm -rf $TMPDIR; exit 1' 0 1 2 3 13 15

# push it to the functions.. no reason to be global
OUT="$TMPDIR/security.out"

# create SEC_DATA and SEC_VAR. directories used to store and persist data
create_secdir

# initialize rmp-md5, sbit, write, device and write-bin
initialize_secfiles $SEC_DATA

# get the fs mount points
MNT=`/bin/mount | grep -E "^/dev/"  | cut -d' ' -f 3 | grep -v "/media" | xargs  echo "/dev/"`

# set the mailer that will be used
set_mailer

# extended password check
check_guessable_passwords "extended"

# neverlogin check
check_neverlogin $SEC_BIN

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
