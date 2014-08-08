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

# init
for i in "$SEC_DATA/rpm-md5" "$SEC_DATA/sbit" "$SEC_DATA/write" "$SEC_DATA/devices" "$SEC_DATA/write-bin"; do
    if [ ! -e "$i" ] ; then
        touch "$i"
    fi
done

# get the ext2 and reiserfs mount points
MNT=`/bin/mount | grep -E "^/dev/"  | cut -d' ' -f 3 | grep -v "/media" | xargs  echo "/dev/"`

set_mailer

# extended password check
check_guessable_passwords "extended"

# neverlogin check
$SEC_BIN/checkneverlogin > "$OUT"
if [ -s "$OUT" ] ; then
	printf "\nPlease check and perhaps disable the following unused accounts:\n"
	cat "$OUT"
fi

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
