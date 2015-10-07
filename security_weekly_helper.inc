# param mount points
check_suid_sgid () {
    mnt_point=$1
    local output_file=`mktemp -t suid_sgid.XXXX` # TEMPDIR is set but not exported.. does it work?
    ( nice -n 1 find $mnt_point -mount \( -perm -04000 -o -perm -02000 \) -type f | sort | \
        xargs --no-run-if-empty ls -cdl --time-style=long-iso -- > "$SEC_DATA/sbit.new" ) 2> /dev/null
    diff -uw "$SEC_DATA/sbit" "$SEC_DATA/sbit.new" | egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$output_file"
    if [ -s "$output_file" ] ; then
        printf "\nThe following files are suid/sgid:\n"
        cat "$output_file"
    fi
    mv "$SEC_DATA/sbit.new" "$SEC_DATA/sbit"
    rm -f "$output_file"
}

# param mount points
check_writable_executable () {
    mnt_point=$1
    local output_file=`mktemp -t writable_executable.XXXX` # TEMPDIR is set but not exported.. does it work?
    ( nice -n 1 find $mnt_point -mount \( -perm -30 -o -perm -3 \) -type f | sort | \
        xargs --no-run-if-empty ls -cdl --time-style=long-iso -- > "$SEC_DATA/write-bin.new" ) 2> /dev/null
    diff -uw "$SEC_DATA/write-bin" "$SEC_DATA/write-bin.new" | \
        egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$output_file"
    if [ -s "$output_file" ] ; then
        printf "\nThe following program executables are group/world writeable:\n"
        cat "$output_file"
    fi
    mv "$SEC_DATA/write-bin.new" "$SEC_DATA/write-bin"
    rm -f "$output_file"
}

# param mount points
check_world_writable () {
    mnt_point=$1
    local output_file=`mktemp -t world_writable.XXXX` # TEMPDIR is set but not exported.. does it work?
    ( nice -n 1 find $mnt_point -mount -perm -2 \( -type f -o -type d \) -not -perm -01000 | sort > "$SEC_DATA/write.new" ) 2> /dev/null
    diff -uw "$SEC_DATA/write" "$SEC_DATA/write.new" | \
        egrep -v '^\+\+\+ |^--- |^$|^@@' | sed 's/^[+-]/& /' > "$output_file"
    if [ -s "$output_file" ] ; then
        printf "\nThe following files/directories are world writeable and not sticky:\n"
        cat "$output_file"
    fi
    mv "$SEC_DATA/write.new" "$SEC_DATA/write"
    rm -f "$output_file"
}

# params
# $1 = directory for checkneverlogin
check_neverlogin () {
    bin_path=$1
    #
    local output_file=`mktemp -t neverlogin.XXXX` # TEMPDIR is set but not exported.. does it work?

    $bin_path/checkneverlogin > "$output_file"
    if [ -s "$output_file" ] ; then
	    printf "\nPlease check and perhaps disable the following unused accounts:\n"
	    cat "$output_file"
    fi
    rm -f "$output_file"
}
