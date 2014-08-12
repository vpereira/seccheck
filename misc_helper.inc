# misc security checks

# executables should not be in the /etc/aliases file.
function no_exec_in_etcaliases () {
    if [ -s /etc/aliases ]; then
        local output_file=`mktemp -t no_exec_in_etcaliases.XXXX` # TEMPDIR is set but not exported.. does it work?
        grep -v '^#' /etc/aliases | grep '|' > $output_file
        if [ -s "$output_file" ] ; then
                printf "\nThe following programs are executed in your mail via /etc/aliases (bad!):\n"
                cat "$output_file"
        fi
        rm -f "$output_file"
    fi


}

# it doesnt save it to a file like the others.. why?
function check_no_plus () {
    local output_file=`mktemp -t check_no_plus.XXXX` # TEMPDIR is set but not exported.. does it work?
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
    local output_file=`mktemp -t check_rhosts.XXXX` # TEMPDIR is set but not exported.. does it work?
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
    rm -f "$output_file"
}

# Check home directories.  Directories should not be owned by someone else
function check_home_directories_owners () {
    local output_file=`mktemp -t home_directories_owners.XXXX` # TEMPDIR is set but not exported.. does it work?
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

# checking root's login scrips for secure path and umask
function check_root_login_scripts () {
    local output_file=`mktemp -t check_root_login_scripts.0.XXXX` # TEMPDIR is set but not exported.. does it work?
    local tmp_file1=`mktemp -t check_root_login_scripts.1.XXXX` # TEMPDIR is set but not exported.. does it work?
    local tmp_file2=`mktemp -t check_root_login_scripts.2.XXXX` # TEMPDIR is set but not exported.. does it work?
    rhome=/root
    umaskset=no
    list="/etc/csh.cshrc /etc/csh.login"
    for i in $list ; do
            if [ -s "$i" ] ; then
                    if egrep umask $i > /dev/null ; then
                            umaskset=yes
                    fi
                    egrep umask $i |
                    awk '$2 % 100 < 20 \
                            { print "Root umask is group writeable" }
                         $2 % 10 < 2 \
                            { print "Root umask is other writeable" }' >> $output_file
                    SAVE_PATH=$PATH
                    unset PATH 2> /dev/null || PATH="" # redhat ... 
                    /bin/csh -f -s << end-of-csh > /dev/null 2>&1
                            test -f "$i" && (	# still a race
                                source $i
                                /bin/ls -ldcbg \$path > $tmp_file1
                )
    end-of-csh
                    PATH=$SAVE_PATH
                    awk '{
                            if ($9 ~ /^\.$/) {
                                    print "The root path includes .";
                                    next;
                            }
                         }
                         $1 ~ /^d....w/ \
            { print "Root path directory " $9 " is group writeable." } \
                         $1 ~ /^d.......w/ \
            { print "Root path directory " $9 " is other writeable." }' \
                    < $tmp_file1 >> $tmp_file2
            fi
    done
    if [ $umaskset = "no" -o -s "$tmp_file2" ] ; then
        sort -u $tmp_file2 > $output_file
            printf "\nChecking root csh paths, umask values:\n$list\n"
            if [ -s "$output_file" ] ; then
                    cat "$output_file"
            fi
            if [ $umaskset = "no" ] ; then
                    printf "\nRoot csh startup files do not set the umask.\n"
            fi
    fi
    > $output_file
    > $tmp_file1
    > $tmp_file2
    rhome=/root
    umaskset=no
    list="/etc/profile ${rhome}/.profile ${rhome}/.bashrc ${rhome}/.bash_login"
    for i in $list; do
            if [ -s "$i" ] ; then
                    if egrep umask $i > /dev/null ; then
                            umaskset=yes
                    fi
                    egrep umask $i |
                    awk '$2 % 100 < 20 \
                            { print "Root umask is group writeable" } \
                         $2 % 10 < 2 \
                            { print "Root umask is other writeable" }' >> $output_file
                    SAVE_PATH=$PATH
                    unset PATH 2> /dev/null || PATH="" # redhat again ...
                    /bin/sh << end-of-sh > /dev/null 2>&1
                            file "$i" | grep -qw text && . $i
                            list=\`echo \$PATH | /usr/bin/sed -e 's/:/ /g'\`
                /bin/ls -ldgbT \$list > $tmp_file1
    end-of-sh
                    PATH=$SAVE_PATH
                    awk '{
                            if ($9 ~ /^\.$/) {
                                    print "The root path includes .";
                                    next;
                            }
                         }
                         $1 ~ /^d....w/ \
            { print "Root path directory " $9 " is group writeable." } \
                         $1 ~ /^d.......w/ \
            { print "Root path directory " $9 " is other writeable." }' \
                    < $tmp_file1 >> $tmp_file2

            fi
    done
    if [ $umaskset = "no" -o -s "$tmp_file2" ] ; then
        sort -u $tmp_file2 > $output_file
            printf "\nChecking root sh paths, umask values:\n$list\n"
            if [ -s "$output_file" ] ; then
                    cat "$output_file"
            fi
            if [ $umaskset = "no" ] ; then
                    printf "\nRoot sh startup files do not set the umask.\n"
            fi
    fi
    rm -f "$output_file" "$tmp_file1" "$tmp_file2"
}
