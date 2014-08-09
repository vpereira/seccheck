# misc security checks

function no_exec_in_etcaliases () {
    # executables should not be in the /etc/aliases file.
    if [ -s /etc/aliases ]; then
        grep -v '^#' /etc/aliases | grep '|' > $OUT
        if [ -s "$OUT" ] ; then
                printf "\nThe following programs are executed in your mail via /etc/aliases (bad!):\n"
                cat "$OUT"
        fi
    fi


}


function check_no_plus () {
    list="/etc/hosts.equiv /etc/shosts.equiv /etc/hosts.lpd"
    for f in $list ; do
            if [ -s "$f" ] ; then
                    awk '{
                            if ($0 ~ /^\+@.*$/)
                                    next;
                            if ($0 ~ /^\+.*$/)
                                    printf("\nPlus sign in the file %s\n", FILENAME);
                    }' $f
            fi
    done
}

# .rhosts check
function check_rhosts () {
    output_file=`mktemp -t check_rhosts.XXXX` # TEMPDIR is set but not exported.. does it work?
    awk -F: '{ print $1 " " $6 }' /etc/passwd |
    while read uid homedir; do
            for j in .rhosts .shosts; do
                    if [ -s ${homedir}/$j ] ; then
                            rhost=`ls -lcdbg ${homedir}/$j|sed 's/[%\]/_/g'`
                printf "$uid: $rhost\n"
                test -f "$j" && { # still a race, however ...
                    if egrep \\+ ${homedir}/$j > /dev/null ; then
                    printf "\t(has got a plus (+) sign!)\n"
                    fi
                }
                    fi
            done
    done > $output_file
    if [ -s "$output_file" ] ; then
            printf "\nChecking for users with .rhosts/.shosts files.\n"
            cat "$output_file"
    fi
}

# Check home directories.  Directories should not be owned by someone else
function check_home_directories_owners () {
    output_file=`mktemp -t home_directories_owners.XXXX` # TEMPDIR is set but not exported.. does it work?
    awk -F: '/^[^+-]/ { print $1 " " $6 }' /etc/passwd | \
    while read uid homedir; do
            if [ -d ${homedir}/ ] ; then
                    file=`ls -ldb ${homedir}|sed 's/[%\]/_/g'`
                    printf "$uid $file\n"
            fi
    done |
    awk '$1 != $4 && $4 != "root" \
            { print "user " $1 " : home directory is owned by " $4 }
         $2 ~ /^-....w/ \
            { print "user " $1 " : home directory is group writeable" }
         $2 ~ /^-.......w/ \
            { print "user " $1 " : home directory is other writeable" }' > $output_file
    if [ -s "$output_file" ] ; then
            printf "\nChecking home directories.\n"
            sort -u "$output_file"
    fi
    rm -f "$output_file"
}


# Files that should not be owned by someone else or writeable.
function check_special_files_owner () {
    output_file=`mktemp -t specia_files_owner.XXXX` # TEMPDIR is set but not exported.. does it work?
    list=".bashrc .bash_profile .bash_login .bash_logout .cshrc .emacs .exrc \
    .forward .klogin .login .logout .profile .tcshrc .fvwmrc .inputrc .kshrc \
    .nexrc .screenrc .ssh .ssh/config .ssh/authorized_keys .ssh/environment \
    .ssh/known_hosts .ssh/rc .twmrc .xsession .xinitrc .Xdefaults .rhosts \
    .shosts .Xauthority .pgp/secring.pgp .ssh/identity .ssh/random_seed \
    .pgp/randseed.bin .netrc .exrc .vimrc .viminfo"
    awk -F: '/^[^+-]/ { print $1 " " $6 }' /etc/passwd | \
    while read uid homedir; do
            for f in $list ; do
                    file=${homedir}/${f}
                    if [ -f "$file" ] ; then
                            printf "$uid $f `ls -ldcb $file|sed 's/[%\]/_/g'`\n"
                    fi
            done
    done |
    awk '$1 != $5 && $5 != "root" \
            { print "user " $1 " " $2 " : file is owned by " $5 }
         $3 ~ /^-....w/ \
            { print "user " $1 " " $2 " : file is group writeable" }
         $3 ~ /^-.......w/ \
            { print "user " $1 " " $2 " : file is other writeable" }' >> $output_file
    if [ -s "$output_file" ] ; then
            printf "\nChecking dot files.\n"
            sort -u "$output_file"
    fi
}
