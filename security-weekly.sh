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

. /basic.inc

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

# password check
if type -p john >/dev/null && type -p unshadow >/dev/null ; then
    echo > $SEC_VAR/dict
    cat /usr/dict/* /var/lib/john/password.lst 2> /dev/null | sort | uniq >> $SEC_VAR/dict

    # Copy passwd file. Use unique name to avoid races when john takes very long
    SEC_PASSWD=$SEC_VAR/passwd.$$
    unshadow /etc/passwd /etc/shadow > $SEC_PASSWD
    nice -n 1 john -single "$SEC_PASSWD" 1> /dev/null 2>&1
    nice -n 1 john -rules -w:$SEC_VAR/dict "$SEC_PASSWD" 1> /dev/null 2>&1
    john -show "$SEC_PASSWD" | sed -n 's/:.*//p' > "$OUT"
    if [ -s "$OUT" ] ; then
        for i in `cat "$OUT"`; do
             $MAILER "$i" << _EOF_
Subject: Please change your Password

Your password for account "$i" is insecure.
Please change it as soon as possible.

Yours,
        Password Checking Robot

_EOF_
        done
        printf "\nThe following user accounts have guessable passwords:\n"
	cat "$OUT"
    fi
else
    echo -e "\nPassword security checking not possible, package "john" not installed."
fi
rm -f $SEC_PASSWD

# neverlogin check
$SEC_BIN/checkneverlogin > "$OUT"
if [ -s "$OUT" ] ; then
	printf "\nPlease check and perhaps disable the following unused accounts:\n"
	cat "$OUT"
fi

# suid/sgid check
( nice -n 1 find $MNT -mount \( -perm -04000 -o -perm -02000 \) -type f | sort | xargs --no-run-if-empty ls -cdl --time-style=long-iso -- > "$SEC_DATA/sbit.new" ) 2> /dev/null
diff -uw "$SEC_DATA/sbit" "$SEC_DATA/sbit.new" | \
	egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$OUT"
if [ -s "$OUT" ] ; then
    printf "\nThe following files are suid/sgid:\n"
    cat "$OUT"
fi
mv "$SEC_DATA/sbit.new" "$SEC_DATA/sbit"

# writeable executable check
( nice -n 1 find $MNT -mount \( -perm -30 -o -perm -3 \) -type f | sort | xargs --no-run-if-empty ls -cdl --time-style=long-iso -- > "$SEC_DATA/write-bin.new" ) 2> /dev/null
diff -uw "$SEC_DATA/write-bin" "$SEC_DATA/write-bin.new" | \
	egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$OUT"
if [ -s "$OUT" ] ; then
    printf "\nThe following program executables are group/world writeable:\n"
    cat "$OUT"
fi
mv "$SEC_DATA/write-bin.new" "$SEC_DATA/write-bin"

# world writable check
( nice -n 1 find $MNT -mount -perm -2 \( -type f -o -type d \) -not -perm -01000 | sort > "$SEC_DATA/write.new" ) 2> /dev/null
diff -uw "$SEC_DATA/write" "$SEC_DATA/write.new" | \
	egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$OUT"
if [ -s "$OUT" ] ; then
    printf "\nThe following files/directories are world writeable and not sticky:\n"
    cat "$OUT"
fi
mv "$SEC_DATA/write.new" "$SEC_DATA/write"

# md5 check
nice -n 1 rpm -Va 2> /dev/null | grep '^5' > "$SEC_DATA/rpm-md5.new"
diff -uw "$SEC_DATA/rpm-md5" "$SEC_DATA/rpm-md5.new" | \
	egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$OUT"
if [ -s "$OUT" ] ; then
    printf "\nThe following programs have got a different md5 checksum since last week:\n"
    cat "$OUT"
fi
mv "$SEC_DATA/rpm-md5.new" "$SEC_DATA/rpm-md5"

# device check
# warning: bug #51004 ls output depends on root's locale and may be less
# then 10 tokens!
( nice -n 1 find $MNT -mount -type c -or -type b | xargs --no-run-if-empty ls -cdl --time-style=long-iso -- | \
	awk '{print $1 " \t" $3 " \t" $4 " \t" $5 " \t" $6 " \t" $9}' | sort +5 \
	> "$SEC_DATA/devices.new" ) 2> /dev/null
diff -uw "$SEC_DATA/devices" "$SEC_DATA/devices.new" | \
	egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$OUT"
if [ -s "$OUT" ] ; then
    printf "\nThe following devices were added:\n"
    cat "$OUT"
fi
mv "$SEC_DATA/devices.new" "$SEC_DATA/devices"

####
#
# Cleaning up
#
rm -rf "$TMPDIR"
exit 0
# END OF SCRIPT
