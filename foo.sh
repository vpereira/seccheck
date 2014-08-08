# param a username
function guessable_password_email {
    RET_TMPL=`sed "s/{guessable_account}/$1/" blurbs/guessable_passwd.txt`
    echo $RET_TMPL
}


