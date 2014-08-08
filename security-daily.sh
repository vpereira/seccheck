#!/bin/sh
####
#
# SuSE daily security check v2.0 by Marc Heuse <marc@suse.de>
#
# most code was ripped from the OpenBSD /etc/security script ;-)
#
####
#
# TODO: maybe directory writable checks for jobs run in crontab
#
. ./basic.inc

source helper.inc

set_tmpdir $0

trap 'rm -rf $TMPDIR; exit 1' 0 1 2 3 13 15
LOG="$TMPDIR/security.log"
ERR="$TMPDIR/security.err"
OUT="$TMPDIR/security.out"
TMP1="$TMPDIR/security.tmp1"
TMP2="$TMPDIR/security.tmp2"

#
# /etc/passwd check
#
PW="/etc/passwd"
awk -F: '{
        if ($0 ~ /^[ 	]*$/) {
                printf("Line %d is a blank line.\n", NR);
                next;
        }
        if ($1 ~ /^[+-]/)
                next;
        if (NF != 7)
                printf("Line %d has the wrong number of fields.\n", NR+1);
        if ($1 == "")
                printf("Line %d has an empty login field.\n", NR);
        else if ($1 !~ /^[A-Za-z0-9][A-Za-z0-9_\.-]*$/)
                printf("Login %s has non-alphanumeric characters.\n", $1);
        if (length($1) > 32)
                printf("Login %s has more than 32 characters.\n", $1);
        if ($2 == "")
                printf("Login %s has no password.\n", $1);
        else if ($2 !~ /^[x*!]+$/)
		printf("Login %s has a real password (it is not shadowed).\n", $1);
        if ($3 == 0 && $1 != "root")
                printf("Login %s has a user id of 0.\n", $1);
        if ($3 == 1 && $1 != "bin")
		printf("Login %s has a user id of 1.\n", $1);
        if ($3 < 0)
                printf("Login %s has a negative user id.\n", $1);
        if ($4 < 0)
                printf("Login %s has a negative group id.\n", $1);
	if ($4 == 0 && $1 != "root")
		printf("Login %s has a group id of 0.\n", $1);
	if ($4 == 1 && $1 != "bin")
		printf("Login %s has a group id of 1.\n", $1);
}' < $PW > $OUT
if [ -s "$OUT" ] ; then
        printf "\nChecking the $PW file:\n"
        cat "$OUT"
fi
awk -F: '{ print $1 }' $PW | sort | uniq -d > $OUT
if [ -s "$OUT" ] ; then
        printf "\n$PW has duplicate user names.\n"
        column "$OUT"
fi
awk -F: '{ print $1 " " $3 }' $PW | sort -n -k2 | tee $TMP1 |
uniq -d -f 1 | awk '{ print $2 }' > $TMP2
if [ -s "$TMP2" ] ; then
        echo -e "\n$PW has duplicate user ids:"
        while read uid; do
                grep -w $uid\$ $TMP1
        done < $TMP2 | column
fi
cp -pf $PW $PW.backup

#
# /etc/shadow check
#
PW="/etc/shadow"
awk -F: '{
        if ($0 ~ /^[ 	]*$/) {
                printf("Line %d is a blank line.\n", NR);
                next;
        }
        if ($1 ~ /^[+-]/)
                next;
        if (NF != 9)
                printf("Line %d has the wrong number of fields.\n", NR+1);
        if ($1 == "")
                printf("Line %d has an empty login field.\n", NR);
        else if ($1 !~ /^[A-Za-z0-9][A-Za-z0-9_-]*$/)
                printf("Login %s has non-alphanumeric characters.\n", $1);
        if (length($1) > 32)
                printf("Login %s has more than 32 characters.\n", $1);
        if ($2 == "")
                printf("Login %s has no password.\n", $1);
	if ($2 != "" && length($2) != 13 && length($2) != 34 &&
	    length($2) != 1 && $2 !~ /^\$[0-9a-f]+\$/)
		printf("Login %s has an unsual password field length\n", $1);
}' < $PW > "$OUT"
if [ -s "$OUT" ] ; then
        printf "\nChecking the $PW file:\n"
        cat "$OUT"
fi
awk -F: '{ print $1 }' $PW | sort | uniq -d > $OUT
if [ -s "$OUT" ] ; then
        printf "\n$PW has duplicate user names.\n"
        column "$OUT"
fi
cp -fp "$PW" "$PW.backup"
#
# /etc/group checking
#
GRP=/etc/group
awk -F: '{
        if ($0 ~ /^[	 ]*$/) {
                printf("Line %d is a blank line.\n", NR);
                next;
        }
        if ($1 ~ /^[+-]/)
                next;
        if (NF != 4)
                printf("Line %d has the wrong number of fields.\n", NR+1);
        if ($1 !~ /^[A-Za-z0-9][A-Za-z0-9_-]*$/)
                printf("Group %s has non-alphanumeric characters.\n", $1);
        if (length($1) > 32)
                printf("Group %s has more than 32 characters.\n", $1);
        if ($3 !~ /[0-9]*/)
                printf("Login %s has a negative group id.\n", $1);
        if (length($4) > 0 && $3 < 3)
		printf("Group %s(%s) has got the following members: %s\n", $1, $3, $4);
}' < $GRP > $OUT
if [ -s "$OUT" ] ; then
        printf "\nChecking the $GRP file:\n"
        cat "$OUT"
fi
awk -F: '{ print $1 }' $GRP | sort | uniq -d > $OUT
if [ -s "$OUT" ] ; then
        printf "\n$GRP has duplicate group names.\n"
        column "$OUT"
fi
#
# checking root's login scrips for secure path and umask
#
> $OUT
> $TMP1
> $TMP2
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
                        { print "Root umask is other writeable" }' >> $OUT
                SAVE_PATH=$PATH
                unset PATH 2> /dev/null || PATH="" # redhat ... 
                /bin/csh -f -s << end-of-csh > /dev/null 2>&1
                        test -f "$i" && (	# still a race
                            source $i
                            /bin/ls -ldcbg \$path > $TMP1
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
                < $TMP1 >> $TMP2
        fi
done
if [ $umaskset = "no" -o -s "$TMP2" ] ; then
	sort -u $TMP2 > $OUT
        printf "\nChecking root csh paths, umask values:\n$list\n"
        if [ -s "$OUT" ] ; then
                cat "$OUT"
        fi
        if [ $umaskset = "no" ] ; then
                printf "\nRoot csh startup files do not set the umask.\n"
        fi
fi
> $OUT
> $TMP1
> $TMP2
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
                        { print "Root umask is other writeable" }' >> $OUT
                SAVE_PATH=$PATH
                unset PATH 2> /dev/null || PATH="" # redhat again ...
                /bin/sh << end-of-sh > /dev/null 2>&1
                        file "$i" | grep -qw text && . $i
                        list=\`echo \$PATH | /usr/bin/sed -e 's/:/ /g'\`
			/bin/ls -ldgbT \$list > $TMP1
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
                < $TMP1 >> $TMP2

        fi
done
if [ $umaskset = "no" -o -s "$TMP2" ] ; then
	sort -u $TMP2 > $OUT
        printf "\nChecking root sh paths, umask values:\n$list\n"
        if [ -s "$OUT" ] ; then
                cat "$OUT"
        fi
        if [ $umaskset = "no" ] ; then
                printf "\nRoot sh startup files do not set the umask.\n"
        fi
fi
#
# Misc. file checks
#
# root/uucp/bin/daemon etc. should be in /etc/ftpusers.
if [ -s /etc/ftpusers ]; then
	> $OUT
	grep -q '^root$' /etc/ftpusers || echo root >> $OUT
	grep -q '^bin$' /etc/ftpusers || echo bin >> $OUT
        grep -q '^uucp$' /etc/ftpusers || echo uucp >> $OUT
        grep -q '^daemon$' /etc/ftpusers || echo daemon >> $OUT
        grep -q '^nobody$' /etc/ftpusers || echo nobody >> $OUT
        grep -q '^lp$' /etc/ftpusers || echo lp >> $OUT
        grep -q '^man$' /etc/ftpusers || echo man >> $OUT
	if [ -s "$OUT" ] ; then
	    printf "\nThe following system accounts are missing in /etc/ftpusers:\n"
	    cat "$OUT"
	fi
fi
# executables should not be in the /etc/aliases file.
if [ -s /etc/aliases ]; then
    grep -v '^#' /etc/aliases | grep '|' > $OUT
    if [ -s "$OUT" ] ; then
            printf "\nThe following programs are executed in your mail via /etc/aliases (bad!):\n"
            cat "$OUT"
    fi
fi
# Files that should not have + signs.
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
# .rhosts check
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
done > $OUT
if [ -s "$OUT" ] ; then
        printf "\nChecking for users with .rhosts/.shosts files.\n"
        cat "$OUT"
fi
# Check home directories.  Directories should not be owned by someone else
# or writeable.
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
        { print "user " $1 " : home directory is other writeable" }' > $OUT
if [ -s "$OUT" ] ; then
        printf "\nChecking home directories.\n"
        sort -u "$OUT"
fi

# Files that should not be owned by someone else or writeable.
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
        { print "user " $1 " " $2 " : file is other writeable" }' >> $OUT
if [ -s "$OUT" ] ; then
        printf "\nChecking dot files.\n"
        sort -u "$OUT"
fi


# Mailboxes should be owned by user and unreadable.
check_mailboxes_owned_by_user_and_unreadable

ls -cl /var/spool/mail | sed 1d | \
awk '$3 != $9 \
        { print "user " $9 " mailbox is owned by " $3 }
     $1 != "-rw-------" \
        { print "user " $9 " mailbox is " $1 ", group " $4 }' > $OUT
if [ -s "$OUT" ] ; then
        printf "\nChecking mailbox ownership.\n"
        sort -u "$OUT"
fi

# File systems should not be globally exported.
check_for_globally_exported_fs

# check remote and local devices
check_promisc

# list loaded modules
list_loaded_kernel_modules

# nfs mounts with missing nosuid
nfs_mounted_with_missing_nosuid


# display programs with bound sockets
display_programs_with_bound_sockets


####
#
# Cleaning up
#
rm -rf "$TMPDIR"
exit 0
# END OF SCRIPT
