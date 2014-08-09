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
