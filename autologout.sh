#!/bin/sh
#
# Small shellscript by Alexander Bergmann <abergmann@suse.com> which checks 
# for idle user terminals and kills them where applicable. Parameters can be
# found in the configuration file autologout.conf.
# 
PATH="/usr/bin:/bin:/usr/sbin:/sbin"

. /etc/security/autologout.conf

# Default Values
DRY_RUN=0
SHOW_CONF=0

# Our datasets
declare -a USER
declare -a GROUP
declare -a TTY
declare -a IDLE
declare -i SESSIONS

# Return tty idle time in seconds
function tty_idle() {
	EPOCH=`date +%s`
	ACCESS=`stat --format=%X ${1}`
	echo $(($EPOCH-$ACCESS))
}

# Format input seconds into minutes/hours/days
function format_time() {
        SEC=$(($1%60))
        SEC=`printf "%02d" $SEC`
        MIN=$(($1/60))
	if [ $MIN -gt 59 ]; then
		HOUR=$(($MIN/60))
		MIN=$(($MIN%60))
		MIN=`printf "%02d" $MIN`
		if [ $HOUR -gt 24 ]; then
			DAY=$(($HOUR/24))
			HOUR=$(($HOUR%24))
			echo "${DAY}d ${HOUR}:${MIN}:${SEC}"
		else
			echo "${HOUR}:${MIN}:${SEC}"
		fi
	else	
		echo "${MIN}:${SEC}"
	fi
}

# Initialize datasets for active terminals
function init_db() {
	local i=0
	for j in `w -hn | awk '{print $1";"$2}'`; do
		if [ -c /dev/${j#*;} ]; then
			USER[$i]="${j%;*}"
			TTY[$i]="/dev/${j#*;}"
			IDLE[$i]=`tty_idle ${TTY[$i]}`
			GROUP[$i]=`id ${USER[$i]} | awk -F '[()]' '{print $(4)}'`
			let i++
		fi
	done
	# Exit if no user is logged in.
	if [ $i -eq 0 ]; then
		exit
	fi
} 

# Send message to terminal
function send_msg() {
	MIN=`format_time ${IDLE[$1]}`
	MESSAGE=""
	if [ $DRY_RUN -eq 1 ]; then
		MESSAGE="\nDry Run: This terminal will not be terminated.\n" 
	fi
	MESSAGE="${MESSAGE}\n${USER[$1]}: You've been idle for ${MIN} min (allowed ${TTY_TIMEOUT_TMP} min)."
	MESSAGE="${MESSAGE}\nYou'll be logged off in ${DELAY_TIMEOUT_TMP} sec unless you hit a key.\n"
	echo -e "${MESSAGE}" | write ${USER[$1]} ${TTY[$1]}
}

# Kill terminal 
function killit() {
	sleep ${DELAY_TIMEOUT_TMP}
	NEW_IDLE=`tty_idle ${TTY[$1]}`
	if [ $((${NEW_IDLE}/60)) -ge ${TTY_TIMEOUT_TMP} ]; then
		PIDS=`ps -eo pid,tty | grep ${TTY[$1]#/dev/} | awk '{print $1}' | tr '\n' ' '`
		kill -HUP $PIDS &> /dev/null
		MIN=`format_time ${NEW_IDLE}`
		logger "autologout: Terminated ${USER[$1]}:${GROUP[$1]} on ${TTY[$1]} after being idle for ${MIN} (allowed ${TTY_TIMEOUT_TMP} min)."
		sleep $KILL_WAIT
		for pid in $PIDS; do
			if kill -0 $pid &> /dev/null; then 
				kill -TERM $pid &> /dev/null
				sleep 2
				if kill -0 $pid &> /dev/null; then
					kill -KILL $pid &> /dev/null
				fi
			fi
		done
	fi
}

# Check for SSH session
function check_ssh() {
	USERID=`id -u ${USER[$1]}`
	SSH_PS=`ps -eo uid,tty,cmd | grep -E 'sshd:.*@' | grep "${TTY[$1]#/dev/}" | grep -v grep | awk -v uid="${USERID}" '$1 == uid {print $4}'`
	SSH_TTY=${SSH_PS##${USER[$1]}@}
	echo "/dev/${SSH_TTY}"
}

# Check rule configuration
function check_rule() {
	local i=0
	# Load Defaults
	CHECK_TIMEOUT=$TTY_TIMEOUT
	CHECK_DELAY=$DEFAULT_DELAY
	TMP_TIMEOUT=""
	TMP_DELAY=""
	for ((i = 0; i < ${#LOGOUTCONF[@]}; i++)); do
		conf=${LOGOUTCONF[i]%% *}
		case ${conf%:*} in
			group)
				if [ "${conf#*:}" = "${GROUP[$1]}" ]; then
					TMP_TIMEOUT=`echo ${LOGOUTCONF[i]} | awk -F '[: ]' '$3 == "idle" {print $4}; $5 == "idle" {print $6}'`
					TMP_DELAY=`echo ${LOGOUTCONF[i]} | awk -F '[: ]' '$3 == "delay" {print $4}; $5 == "delay" {print $6}'`
				fi
				;;
			user)
				if [ "${conf#*:}" = "${USER[$1]}" ]; then
					TMP_TIMEOUT=`echo ${LOGOUTCONF[i]} | awk -F '[: ]' '$3 == "idle" {print $4}; $5 == "idle" {print $6}'`
					TMP_DELAY=`echo ${LOGOUTCONF[i]} | awk -F '[: ]' '$3 == "delay" {print $4}; $5 == "delay" {print $6}'`
				fi
				;;
			tty)
				if [ "${conf#*:}" = "${TTY[$1]}" ]; then
					TMP_TIMEOUT=`echo ${LOGOUTCONF[i]} | awk -F '[: ]' '$3 == "idle" {print $4}; $5 == "idle" {print $6}'`
					TMP_DELAY=`echo ${LOGOUTCONF[i]} | awk -F '[: ]' '$3 == "delay" {print $4}; $5 == "delay" {print $6}'`
				fi
				;;
			ssh)
				if [ "`check_ssh $1`" = "${TTY[$1]}" ]; then
					TMP_TIMEOUT=`echo ${LOGOUTCONF[i]} | awk -F '[: ]' '$2 == "idle" {print $3}; $4 == "idle" {print $5}'`
					TMP_DELAY=`echo ${LOGOUTCONF[i]} | awk -F '[: ]' '$2 == "delay" {print $3}; $4 == "delay" {print $5}'`
				fi
				;;
		esac
	done
	if [ "x$TMP_TIMEOUT" != "x" ]; then
		CHECK_TIMEOUT=$TMP_TIMEOUT
	fi
	if [ "x$TMP_DELAY" != "x" ]; then
		CHECK_DELAY=$TMP_DELAY
	fi
	echo "$CHECK_TIMEOUT:$CHECK_DELAY"
}

# Check terminal idle time and compare with timeout configuration
function check_idle() {
	local i=0
	if [ $DRY_RUN -eq 1 ]; then
		echo "Autologout: Dry Run"
	fi
	for ((i = 0 ; i < ${#USER[@]}; i++)); do
		#TIMEOUT=`check_rule $i`
		LOGOUT=""
		CONF_TIMEOUT=`check_rule $i`
		TTY_TIMEOUT_TMP=${CONF_TIMEOUT%:*}
		DELAY_TIMEOUT_TMP=${CONF_TIMEOUT#*:}
		MIN=`format_time ${IDLE[$i]}`
		if [ $((${IDLE[$i]}/60)) -ge ${TTY_TIMEOUT_TMP} ]; then
			if [ $DRY_RUN -eq 1 ]; then
				LOGOUT="(Subject to logout)"
				send_msg $i
			else
				send_msg $i
				killit $i &
			fi
		fi
		if [ $DRY_RUN -eq 1 ]; then
			echo -e "Checking: ${USER[$i]}:${GROUP[$i]}  on ${TTY[$i]}  Idle time: ${MIN}  Max: ${TTY_TIMEOUT_TMP} min  ${LOGOUT}"
		fi
	done
}

# Show configuration details
function show_config_details() {
	for rule in $@; do
		case ${rule%:*} in
			idle)
				echo -n " Maximum idle time: ${rule#*:} min ";;
			delay)
				echo -n " Delay till logout: ${rule#*:} sec ";;
		esac
	done
	echo
}

# Show configuration rules
function show_config() {
	echo "Defaults:"
	echo "* maximum idle time: ${TTY_TIMEOUT} min"
	echo "* logout delay: ${DEFAULT_DELAY} sec"
	echo "Rules:"
	local i=0
	for ((i = 0; i < ${#LOGOUTCONF[@]}; i++)); do
		conf=${LOGOUTCONF[i]%% *}
		case ${conf%:*} in
			group)
				echo -n "* GROUP Rule: ${conf#*:} "
				show_config_details ${LOGOUTCONF[i]#* }
				;;
			user)
				echo -n "* USER Rule: ${conf#*:} "
				show_config_details ${LOGOUTCONF[i]#* }
				;;
			tty)
				echo -n "* TTY Rule: ${conf#*:} "
				show_config_details ${LOGOUTCONF[i]#* }
				;;
			ssh)
				echo -n "* SSH Rule:"
				show_config_details ${LOGOUTCONF[i]#* }
				;;
		esac
	done
	if [ $i -eq 0 ]; then
		echo "* No rules defined."
	fi
}

# Initialize Datasets
init_db

# Help output
USAGE="Usage: $0 [OPTION]...\n"\
"  -s           Show configuration.\n"\
"  -d           Configuration dry run.\n"\
"  -c config    Use configuration file.\n"\
"               (default: /etc/security/autologout.conf)"

# Parse command line options
while getopts ":sdc:" opt; do
	case "${opt}" in
		s ) SHOW_CONF=1;;
		d ) DRY_RUN=1;;
		c ) CONF=`readlink -f $OPTARG`
		    if [ "x$CONF" = "x" ]; then
			echo "Error: Please provide a configuration file."
			echo -e "$USAGE"
			exit
		    fi
		    if [ -f $CONF ]; then
		    	source $CONF
		    else
		    	echo "Error: Couldn't find configuration file: '$CONF'"
			echo -e "$USAGE"
			exit
		    fi
		    ;;
		\?) echo -e "$USAGE"
		    exit;;
	esac
done

# Print parsed configuration
if [ $SHOW_CONF -eq 1 ]; then
	show_config
	exit
fi

# Start checking terminal idle times
check_idle
exit

