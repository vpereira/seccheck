# user,group and password related functions

function check_passwd () {

    local output_file=`mktemp -t check_passwd.XXXX` # TEMPDIR is set but not exported.. does it work?
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
    }' < $PW > $output_file
    if [ -s "$output_file" ] ; then
            printf "\nChecking the $PW file:\n"
            cat "$output_file"
    fi
    awk -F: '{ print $1 }' $PW | sort | uniq -d > $output_file
    if [ -s "$output_file" ] ; then
            printf "\n$PW has duplicate user names.\n"
            column "$output_file"
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
    rm -f "$output_file"
}

function check_shadow () {
    local output_file=`mktemp -t check_passwd.XXXX` # TEMPDIR is set but not exported.. does it work?
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
    }' < $PW > "$output_file"
    if [ -s "$output_file" ] ; then
            printf "\nChecking the $PW file:\n"
            cat "$output_file"
    fi
    awk -F: '{ print $1 }' $PW | sort | uniq -d > $output_file
    if [ -s "$output_file" ] ; then
            printf "\n$PW has duplicate user names.\n"
            column "$output_file"
    fi
    cp -fp "$PW" "$PW.backup"
    rm -f "$output_file"
}

function check_group () {
    local output_file=`mktemp -t check_group.XXXX` # TEMPDIR is set but not exported.. does it work?
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
    }' < $GRP > $output_file
    if [ -s "$output_file" ] ; then
            printf "\nChecking the $GRP file:\n"
            cat "$output_file"
    fi
    awk -F: '{ print $1 }' $GRP | sort | uniq -d > $output_file
    if [ -s "$output_file" ] ; then
            printf "\n$GRP has duplicate group names.\n"
            column "$output_file"
    fi
    rm -f "$output_file"
}

function check_ftpusers () {
    if [ -s /etc/ftpusers ]; then
        local output_file=`mktemp -t check_ftpusers.XXXX` # TEMPDIR is set but not exported.. does it work?
        grep -q '^root$' /etc/ftpusers || echo root >> $output_file
        grep -q '^bin$' /etc/ftpusers || echo bin >> $output_file
            grep -q '^uucp$' /etc/ftpusers || echo uucp >> $output_file
            grep -q '^daemon$' /etc/ftpusers || echo daemon >> $output_file
            grep -q '^nobody$' /etc/ftpusers || echo nobody >> $output_file
            grep -q '^lp$' /etc/ftpusers || echo lp >> $output_file
            grep -q '^man$' /etc/ftpusers || echo man >> $output_file
        if [ -s "$output_file" ] ; then
            printf "\nThe following system accounts are missing in /etc/ftpusers:\n"
            cat "$output_file"
        fi
        rm -f "$output_file"
    fi
}

