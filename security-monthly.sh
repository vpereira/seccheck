#!/bin/sh
####
#
# SuSE monthly security check v2.0 by Marc Heuse <marc@suse.de>
#
####

. ./basic.inc

source ./helper.inc

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

echo -e '\nNOTE: have you checked http://www.novell.com/products/security.html for security updates?!\n'

cat "$OLD1"

check_guessable_passwords "quick"

echo -e '\nComplete list of unused user accounts which have a password assigned:'
$SEC_BIN/checkneverlogin

echo -e '\nComplete list of writeable and executeable programs:'
cat "$SEC_DATA/write-bin"

echo -e '\nComplete list of suid/sgid files:'
cat "$SEC_DATA/sbit"

echo -e '\nComplete list of world writeable files:'
cat "$SEC_DATA/write"

echo -e '\nComplete list of all changed installed packages:'
cat "$SEC_DATA/rpm-md5"

echo -e '\nComplete list of (char/block) devices:'
cat "$SEC_DATA/devices"

exit 0
