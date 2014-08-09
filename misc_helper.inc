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
