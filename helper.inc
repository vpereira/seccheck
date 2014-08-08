#
# functions used by all modules
#
# param: program name
function set_tmpdir () {
    TMPDIR=`/bin/mktemp -d /tmp/$1.XXXXXX` || exit 1
}

function run_sysconfig_seccheck () {
    test -e /etc/sysconfig/seccheck && . /etc/sysconfig/seccheck
}

function syntax () {
    /bin/echo "Syntax: $0 "'daily|weekly|monthly'
    exit 1
}

function set_mailer () {
    test -z "$MAILER" && test -x "/usr/sbin/sendmail" && MAILER="/usr/sbin/sendmail"
    test -z "$MAILER" && test -x "/usr/bin/mailx" && MAILER="/usr/bin/mailx"
    test -z "$MAILER" && test -x "/usr/lib/sendmail" && MAILER="/usr/lib/sendmail"
    test -z "$MAILER" && MAILER="mail"
    test -n "$MAILER" && export MAILER
}

function create_secdir () {
    if [ ! -d "$SEC_VAR" ]; then
        rm -rf "$SEC_VAR"
        mkdir "$SEC_VAR" || exit 1
    fi

    if [ ! -d "$SEC_DATA" ]; then
        rm -rf "$SEC_DATA"
        mkdir "$SEC_DATA" || exit 1
    fi
}

# param a username
function guessable_password_email {
    RET_TMPL=`sed "s/{guessable_account}/$1/" blurbs/guessable_passwd.txt`
    echo $RET_TMPL
}



# use john the ripper to check guessable passwords
# if you pass "quick" as argument it will simple try to find easy 
# guessable passwords. otherwise it will use a dictionary
function check_guessable_passwords() {
    if type -p john >/dev/null && type -p unshadow >/dev/null ; then
        # Copy passwd file. Use unique name to avoid races when john takes very long
        SEC_PASSWD=$SEC_VAR/passwd.$$
        OUT="$TMPDIR/security.out" # random name please
        echo -e '\nComplete list of user accounts with guessable passwords:'
        unshadow /etc/passwd /etc/shadow > $SEC_PASSWD
        if [ "$1" != "quick" ]; then
            nice -n 1 john -single "$SEC_PASSWD" 1> /dev/null 2>&1
            nice -n 1 john -rules -w:$SEC_VAR/dict "$SEC_PASSWD" 1> /dev/null 2>&1
        fi

        john -show "$SEC_PASSWD" | sed -n 's/:.*//p' > "$OUT"

        if [ "$1" != "quick" ]; then
            if [ -s "$OUT" ] ; then
                for i in `cat "$OUT"`; do
                    $MAILER guessable_password_email "$i"  # set mailer
                done
            end
        fi
        cat $OUT
        /bin/rm -f $SEC_VAR/passwd
        /bin/rm -f $OUT
    fi

}
