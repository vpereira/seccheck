#
# functions used by all modules
#
# param: prefix for filename
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


# set which mailer should be used
function set_mailer () {
    test -z "$MAILER" && test -x "/usr/sbin/sendmail" && MAILER="/usr/sbin/sendmail"
    test -z "$MAILER" && test -x "/usr/bin/mailx" && MAILER="/usr/bin/mailx"
    test -z "$MAILER" && test -x "/usr/lib/sendmail" && MAILER="/usr/lib/sendmail"
    test -z "$MAILER" && MAILER="mail"
    test -n "$MAILER" && export MAILER
}

# create necessary directories
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
# template engine to substitute a variable in a text and prepare it
# to be sent per email
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

# daily changes per email
# params
# OLD1, OUT1
function send_daily_changes () {
    local old1=$1
    local out1=$2
    
    cat <<-EOF
    To: $SECCHK_USER
    Subject: Local Daily Security for `hostname`: Changes

    Daily security check $VERSION by Marc Heuse <marc@suse.de>
    $BLURB

    Changes in your daily security configuration of `hostname`:

EOF

    /usr/bin/diff -u -w "$old1" "$out1" | sed 's/^@@.*/\ * Changes (+: new entries, -: removed entries):\ /' | \egrep '^[+*-]|^$' |sed 's/^+++/NEW:/' | sed 's/^---/OLD:/' | sed 's/^[+-]/& /' | $MAILER "$SECCHK_USER" 
    /bin/mv "$out1" "$old1"
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



# param mount points
function check_new_devices () {
    mnt_point=$1
    local output_file=`mktemp -t new_devices.XXXX` # TEMPDIR is set but not exported.. does it work?
    # warning: bug #51004 ls output depends on root's locale and may be less
    # then 10 tokens!
    ( nice -n 1 find $mnt_point -mount -type c -or -type b | xargs --no-run-if-empty ls -cdl --time-style=long-iso -- | \ awk '{print $1 " \t" $3 " \t" $4 " \t" $5 " \t" $6 " \t" $9}' | sort +5 \ > "$SEC_DATA/devices.new" ) 2> /dev/null
    diff -uw "$SEC_DATA/devices" "$SEC_DATA/devices.new" |egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$output_file"
    if [ -s "$output_file" ] ; then
        printf "\nThe following devices were added:\n"
        cat "$output_file"
    fi
    mv "$SEC_DATA/devices.new" "$SEC_DATA/devices"
    rm -f "$output_file"
}

# check md5sum from files
function check_md5 () {
    local output_file=`mktemp -t md5.XXXX` # TEMPDIR is set but not exported.. does it work?
    nice -n 1 rpm -Va 2> /dev/null | grep '^5' > "$SEC_DATA/rpm-md5.new"
    diff -uw "$SEC_DATA/rpm-md5" "$SEC_DATA/rpm-md5.new" | \
        egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$output_file"
    if [ -s "$output_file" ] ; then
        printf "\nThe following programs have got a different md5 checksum since last week:\n"
        cat "$output_file"
    fi
    mv "$SEC_DATA/rpm-md5.new" "$SEC_DATA/rpm-md5"
    rm -f "$output_file"
}

function display_programs_with_bound_sockets () {
    if [ -x /usr/bin/lsof ]; then
        printf "\nThe following programs have got bound sockets:\n"
        /usr/bin/lsof -i -n -P | egrep 'UDP|TCP.*LISTEN' | sed 's/....[0-9]u  IP.*     /   /' | 
        sed 's/  FD   TYPE DEVICE SIZE NODE NAME/PROTO PORT/' | 
        sed 's/ [0-9][0-9]* / /'| 
        sed 's/ PID / /'| sort -u
    fi

}

function nfs_mounted_with_missing_nosuid () {
    local output_file=`mktemp -t mounted_with_missing_nosuid.XXXX` # TEMPDIR is set but not exported.. does it work?
    /bin/mount | /usr/bin/grep -v nosuid | /usr/bin/grep ' nfs ' |sort > $output_file
    if [ -s "$output_file" ] ; then
        printf "\nThe following NFS mounts haven't got the nosuid option set:\n"
        cat "$output_file"
    fi
    rm -f "$output_file"
}

function list_loaded_kernel_modules () {
    local output_file=`mktemp -t loaded_kernel_modules.XXXX` # TEMPDIR is set but not exported.. does it work?
    test -e /proc/modules && { 
        lsmod 2> /dev/null | grep -v '^Module .* Used by$' | awk '{print$1}' | sort > $output_file
        if [ -s "$output_file" ] ; then
            printf "\nThe following loadable kernel modules are currently installed:\n"
            cat "$output_file"
        fi
    }
    rm -f "$output_file"
}


function check_for_globally_exported_fs () {

    local output_file=`mktemp -t globally_exported_fs.XXXX` # TEMPDIR is set but not exported.. does it work?

    if [ -s /etc/exports ] ; then
            awk '{
                    if (($1 ~ /^#/) || ($1 ~ /^$/))
                            next;
                    readonly = 0;
                    for (i = 2; i <= NF; ++i) {
                            if ($i ~ /^-ro$/)
                                    readonly = 1;
                            else if ($i !~ /^-/)
                                    next;
                    }
                    if (readonly)
                            print "File system " $1 " globally exported, read-only.";
            else
                            print "File system " $1 " globally exported, read-write.";
            }' < /etc/exports > $output_file
            if [ -s "$output_file" ] ; then
                    printf "\nChecking for globally exported file systems.\n"
                    cat "$output_file"
            fi
            rm -f "$output_file"
    fi
}
