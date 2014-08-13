#!/bin/sh
####
#
# SuSE weekly security check v2.0 by Marc Heuse <marc@suse.de>
#
####
#
# TODO /etc /home /home/.* permissions
#

# TODO re-enable it
. /etc/sysconfig/seccheck


MY_DIR=$(dirname $(readlink -f $0))
. $MY_DIR/basic.inc

source $MY_DIR/helper.inc
source $MY_DIR/user_group_password_helper.inc
source $MY_DIR/misc_helper.inc



set_tmpdir "security-weekly.sh"

trap 'rm -rf $TMPDIR; exit 1' 0 1 2 3 13 15

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

check_suid_sgid $MNT

check_writable_executable $MNT

check_world_writable $MNT

check_new_devices $MNT


####
#
# Cleaning up
#
rm -rf "$TMPDIR"
exit 0
# END OF SCRIPT
