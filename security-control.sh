#!/bin/sh
####
#
# SuSE master control security mechanism for the daily/weekly/monthly
# security checks, by Marc Heuse <marc@suse.de>, version 2.0
#
####
VERSION="v3.0"

. /basic.inc

source ./helper.inc

run_sysconfig_seccheck

test -z "$SECCHK_USER" && SECCHK_USER="root"

if test "$START_SECCHK" != yes -a "$RUN_FROM_CRON" = yes; then
  #echo "seccheck disabled by START_SECCHK" 
  exit 0
fi


BLURB=`cat blurbs/security_control.txt`



test -z "$1" && syntax


set_mailer

test -z "$MAILER" && echo "Can not find a suitable mailer!"
test -z "$MAILER" && exit 1

test -z "$SEC_BIN" && SEC_BIN="/usr/lib/secchk"
test -z "$SEC_VAR" && SEC_VAR="/var/lib/secchk"

SEC_DATA="$SEC_VAR/data"
OUT1="$SEC_VAR/security-report-daily.new"
OLD1="$SEC_VAR/security-report-daily"
OUT2="$SEC_VAR/security-report-weekly.new"
OLD2="$SEC_VAR/security-report-weekly"
OLD3="$SEC_VAR/security-report-monthly"

create_secdir 

for i in "$OLD1" "$OLD2" "$OLD3" ; do
    if [ "$i" != "" ]; then
        if [ ! -e "$i" ]; then
   	    touch "$i"
        fi
    fi
done

test "$1" = "daily" && (
 /bin/sh "$SEC_BIN/security-daily.sh" 1> "$OUT1"
 /usr/bin/diff -q -w "$OLD1" "$OUT1" 1> /dev/null || (
    {
	cat <<-EOF
	To: $SECCHK_USER
	Subject: Local Daily Security for `hostname`: Changes

	Daily security check $VERSION by Marc Heuse <marc@suse.de>
	$BLURB

	Changes in your daily security configuration of `hostname`:

EOF

      /usr/bin/diff -u -w "$OLD1" "$OUT1" | sed 's/^@@.*/\
* Changes (+: new entries, -: removed entries):\
	/' | egrep '^[+*-]|^$' |sed 's/^+++/NEW:/' | sed 's/^---/OLD:/' | sed 's/^[+-]/& /'
    } | $MAILER "$SECCHK_USER"
    /bin/mv "$OUT1" "$OLD1"
 )
 rm -f "$OUT1"
)

test "$1" = "weekly" && (
 /bin/sh "$SEC_BIN/security-weekly.sh" 1> "$OUT2"
 if [ -s "$OUT2" ]; then
    {
      	cat <<-EOF
	To: $SECCHK_USER
	Subject: Local Weekly Security for `hostname`: Changes

	Weekly security check $VERSION by Marc Heuse <marc@suse.de>
	$BLURB

	Changes in your weekly security configuration of `hostname`:

EOF
      cat "$OUT2"
    } | $MAILER "$SECCHK_USER"
    mv "$OUT2" "$OLD2"
 fi
 rm -f "$OUT2"
)

test "$1" = "monthly" && (
 test -s "$OLD1" || /bin/sh "$SEC_BIN/security-daily.sh" 1> "$OLD1"
 test -e "$SEC_DATA/devices" || /bin/sh "$SEC_BIN/security-weekly.sh" 1> "$OLD2"
 {
 	cat <<-EOF
	To: $SECCHK_USER
	Subject: Local Monthly Security for `hostname`: Complete

	Monthly security check $VERSION by Marc Heuse <marc@suse.de>
	$BLURB

	Monthly security check $VERSION by Marc Heuse <marc@suse.de>

EOF
      /bin/sh "$SEC_BIN/security-monthly.sh"
 } | tee "$OLD3" | $MAILER "$SECCHK_USER"
)

exit 0
