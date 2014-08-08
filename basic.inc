###
#
# Security Check basic definitions 
#
##

PATH="/usr/bin:/bin:/usr/sbin:/sbin"
umask 077

test -z "$SEC_BIN" && SEC_BIN="/usr/lib/secchk"
test -z "$SEC_VAR" && SEC_VAR="/var/lib/secchk"
SEC_DATA="$SEC_VAR/data"
