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
    ret_tmpl=`sed "s/{guessable_account}/$1/" blurbs/guessable_passwd.txt`
    echo $ret_tmpl
}

# those files are needed 
# param $1 = SEC_DATA, normally /var/lib/seccheck/data
function initialize_secfiles () {
    for i in "rpm-md5" "sbit" "write" "devices" "write-bin"; do
        if [ ! -e "$1/$i" ] ; then
            touch "$1/$i"
        fi
    done
}

# params 
# $1 = directory for checkneverlogin
function check_neverlogin () {
    bin_path=$1
    # 
    output_file=`mktemp -t neverlogin.XXXX` # TEMPDIR is set but not exported.. does it work?

    $bin_path/checkneverlogin > "$output_file"
    if [ -s "$output_file" ] ; then
	    printf "\nPlease check and perhaps disable the following unused accounts:\n"
	    cat $output_file
    fi
    rm -f $output_file
}

# use john the ripper to check guessable passwords
# if you pass "quick" as argument it will simple try to find easy 
# guessable passwords. otherwise it will use a dictionary
function check_guessable_passwords () {

    if type -p john >/dev/null && type -p unshadow >/dev/null ; then
        # Copy passwd file. Use unique name to avoid races when john takes very long
        SEC_PASSWD="$SEC_VAR/passwd.$$"
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
            fi
        fi
        cat $OUT
        /bin/rm -f $SEC_VAR/passwd
        /bin/rm -f $OUT
    fi
}

# param mount points and output-file
function check_suid_sgid () {
    mnt_point=$1
    output_file=`mktemp -t suid_sgid.XXXX` # TEMPDIR is set but not exported.. does it work?
    ( nice -n 1 find $mnt_point -mount \( -perm -04000 -o -perm -02000 \) -type f | sort | \
        xargs --no-run-if-empty ls -cdl --time-style=long-iso -- > "$SEC_DATA/sbit.new" ) 2> /dev/null
    diff -uw "$SEC_DATA/sbit" "$SEC_DATA/sbit.new" | \
        egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$output_file"
    if [ -s "$output_file" ] ; then
        printf "\nThe following files are suid/sgid:\n"
        cat "$output_file"
    fi
    mv "$SEC_DATA/sbit.new" "$SEC_DATA/sbit"
    rm -f $output_file
}

# param mount points and output-file
function check_writable_executable () {
    mnt_point=$1
    output_file=`mktemp -t writable_executable.XXXX` # TEMPDIR is set but not exported.. does it work?
    ( nice -n 1 find $mnt_point -mount \( -perm -30 -o -perm -3 \) -type f | sort | \
        xargs --no-run-if-empty ls -cdl --time-style=long-iso -- > "$SEC_DATA/write-bin.new" ) 2> /dev/null
    diff -uw "$SEC_DATA/write-bin" "$SEC_DATA/write-bin.new" | \
        egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$output_file"
    if [ -s "$output_file" ] ; then
        printf "\nThe following program executables are group/world writeable:\n"
        cat "$output_file"
    fi
    mv "$SEC_DATA/write-bin.new" "$SEC_DATA/write-bin"
    rm -f $output_file
}

# param mount points and output-file
function check_world_writable () {
    mnt_point=$1
    output_file=`mktemp -t world_writable.XXXX` # TEMPDIR is set but not exported.. does it work?
    ( nice -n 1 find $mnt_point -mount -perm -2 \( -type f -o -type d \) -not -perm -01000 | sort > "$SEC_DATA/write.new" ) 2> /dev/null
    diff -uw "$SEC_DATA/write" "$SEC_DATA/write.new" | \
        egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$output_file"
    if [ -s "$output_file" ] ; then
        printf "\nThe following files/directories are world writeable and not sticky:\n"
        cat "$output_file"
    fi
    mv "$SEC_DATA/write.new" "$SEC_DATA/write"
    rm -f $output_file
}

# param mount points and output-file
function check_new_devices () {
    mnt_point=$1
    output_file=`mktemp -t new_devices.XXXX` # TEMPDIR is set but not exported.. does it work?
    # warning: bug #51004 ls output depends on root's locale and may be less
    # then 10 tokens!
    ( nice -n 1 find $mnt_point -mount -type c -or -type b | xargs --no-run-if-empty ls -cdl --time-style=long-iso -- | \
    awk '{print $1 " \t" $3 " \t" $4 " \t" $5 " \t" $6 " \t" $9}' | sort +5 \
    > "$SEC_DATA/devices.new" ) 2> /dev/null
    diff -uw "$SEC_DATA/devices" "$SEC_DATA/devices.new" | \
    egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$output_file"
    if [ -s "$output_file" ] ; then
        printf "\nThe following devices were added:\n"
        cat "$output_file"
    fi
    mv "$SEC_DATA/devices.new" "$SEC_DATA/devices"
    rm -f $output_file
}

# param output-file
function check_md5 () {
    output_file=`mktemp -t md5.XXXX` # TEMPDIR is set but not exported.. does it work?
    nice -n 1 rpm -Va 2> /dev/null | grep '^5' > "$SEC_DATA/rpm-md5.new"
    diff -uw "$SEC_DATA/rpm-md5" "$SEC_DATA/rpm-md5.new" | \
        egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$output_file"
    if [ -s "$output_file" ] ; then
        printf "\nThe following programs have got a different md5 checksum since last week:\n"
        cat "$output_file"
    fi
    mv "$SEC_DATA/rpm-md5.new" "$SEC_DATA/rpm-md5"
    rm -f $output_file
}
