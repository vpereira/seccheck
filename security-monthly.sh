#!/bin/sh
####
#
# SuSE monthly security check v2.0 by Marc Heuse <marc@suse.de>
#
####

MY_DIR=$(dirname $(readlink -f $0))
. $MY_DIR/basic.inc

. $MY_DIR/helper.inc

run_sysconfig_seccheck


OLD1="$SEC_VAR/security-report-daily"
#OLD2="$SEC_VAR/security-report-weekly"
#OLD3="$SEC_VAR/security-report-monthly"

# create SEC_DATA and SEC_VAR. directories used to store and persist data
create_secdir

# initialize rmp-md5, sbit, write, device and write-bin
initialize_secfiles $SEC_DATA

# XXX: is it really necessary?
if [ ! -e "$OLD1" ];then
    touch "$OLD1"
fi
#for i in "$OLD1" "$OLD2" "$OLD3" ; do
#    if [ "$i" != "" ]; then
#        if [ ! -e "$i" ]; then
#    	    touch "$i"
#        fi
#    fi
#done

echo '
NOTE: have you checked http://www.novell.com/products/security.html for security updates?!
'

cat "$OLD1"

check_guessable_passwords "quick"

echo "
Complete list of unused user accounts which have a password assigned:"
$SEC_BIN/checkneverlogin

echo "
Complete list of writeable and executeable programs:"
cat "$SEC_DATA/write-bin"

echo "
Complete list of suid/sgid files:"
cat "$SEC_DATA/sbit"

echo "
Complete list of world writeable files:"
cat "$SEC_DATA/write"

echo "
Complete list of all changed installed packages:"
cat "$SEC_DATA/rpm-md5"

echo "
Complete list of (char/block) devices:"
cat "$SEC_DATA/devices"

exit 0
