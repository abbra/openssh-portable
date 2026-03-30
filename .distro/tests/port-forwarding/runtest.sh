#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/openssh/Sanity/port-forwarding
#   Description: Testing port forwarding (ideally all possibilities: -L, -R, -D)
#   Author: Stanislav Zidek <szidek@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2015 Red Hat, Inc.
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation, either version 2 of
#   the License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE.  See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see http://www.gnu.org/licenses/.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include Beaker environment
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="openssh"
USER="user$RANDOM"
FORWARDED=$((RANDOM % 100 + 6800))
LISTEN=$((RANDOM % 100 + 6900))
TIMEOUT=5
MESSAGE="HUGE_SUCCESS"
SSH_OPTIONS="-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm $PACKAGE
        rlFileBackup /etc/ssh/sshd_config
        rlRun "useradd -m $USER"
        rlRun "su - $USER -c \"mkdir .ssh; chmod 700 .ssh; cd .ssh; ssh-keygen -N '' -f id_rsa; cat id_rsa.pub >authorized_keys; chmod 600 authorized_keys\""
        rlRun "echo 'LogLevel DEBUG' >>/etc/ssh/sshd_config"
        rlServiceStart sshd
        # Rate limit service restarts by sleeping
        rlRun "sleep 3s"
        rlRun "IP=\$( ip a |grep 'scope global' |grep -w inet |cut -d'/' -f1 |awk '{ print \$2 }' |tail -1 )"
        rlRun "echo 'IP=$IP'"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

forwarding_test() {
    EXP_RESULT=$1
    FORWARDED=$2
    HOST=$3
    LISTEN=$4

    rlRun "nc -l $LISTEN &>listen.log &"
    LISTEN_PID=$!
    rlWaitForSocket $LISTEN -t $TIMEOUT
    rlRun "ps -fp $LISTEN_PID"
    rlRun "su - $USER -c \"ssh $SSH_OPTIONS -N -L $FORWARDED:$HOST:$LISTEN $USER@localhost &\" &>tunnel.log"
    rlRun "ps -fC ssh"
    rlRun "SSH_PID=\$( pgrep -n -u $USER ssh )"
    rlRun "echo SSH_PID is '$SSH_PID'"
    rlWaitForSocket $FORWARDED -t $TIMEOUT
    rlRun "[[ -n '$SSH_PID' ]] && ps -fp $SSH_PID"
    rlRun "echo '$MESSAGE'|nc localhost $FORWARDED" 0,1

    if [[ $EXP_RESULT == "success" ]]; then
        rlAssertGrep "$MESSAGE" listen.log
    else # failure expected
        rlAssertGrep "open failed" tunnel.log -i
        rlAssertGrep "administratively prohibited" tunnel.log -i
        rlAssertNotGrep "$MESSAGE" listen.log
    fi

    rlRun "kill -9 $LISTEN_PID $SSH_PID" 0,1 "Killing cleanup"
    rlWaitForSocket $LISTEN -t $TIMEOUT --close
    rlWaitForSocket $FORWARDED -t $TIMEOUT --close
    if ! rlGetPhaseState; then
        rlRun "cat listen.log"
        rlRun "cat tunnel.log"
    fi
    rlFileSubmit listen.log tunnel.log
    rlRun "rm -f *.log;"
}

    rlPhaseStartTest "Local forwarding"
        forwarding_test "success" $FORWARDED localhost $LISTEN
        ((FORWARDED+=1))
        ((LISTEN+=1))
    rlPhaseEnd

    rlPhaseStartTest "PermitOpen with 'any'"
        rlFileBackup --namespace permitopen_any /etc/ssh/sshd_config /etc/hosts
        rlRun "echo 'PermitOpen any' >>/etc/ssh/sshd_config"
        rlRun "echo '$IP anyhost1 anyhost2' >>/etc/hosts"
        rlRun "service sshd restart"
        # Rate limit service restarts by sleeping
        rlRun "sleep 3s"
        for i in `seq 3`; do
            forwarding_test "success" $FORWARDED anyhost1 $LISTEN
            forwarding_test "success" $FORWARDED anyhost2 $LISTEN
            ((FORWARDED+=1))
            ((LISTEN+=1))
        done
        rlFileRestore --namespace permitopen_any
    rlPhaseEnd

    if ! rlIsRHEL '<6.7'; then
        # PermitOpen with wildcards is new feature in RHEL-6.7
        rlPhaseStartTest "PermitOpen with port wildcard"
            rlFileBackup --namespace port_wildcard /etc/ssh/sshd_config /etc/hosts
            rlRun "echo 'PermitOpen wildportallow:*' >>/etc/ssh/sshd_config"
            rlRun "echo '$IP wildportallow wildportdeny' >>/etc/hosts"
            rlRun "service sshd restart"
            # Rate limit service restarts by sleeping
            rlRun "sleep 3s"
            forwarding_test "success" $FORWARDED wildportallow $LISTEN
            ((FORWARDED+=1))
            ((LISTEN+=1))
            forwarding_test "failure" $FORWARDED wildportdeny $LISTEN
            ((FORWARDED+=1))
            ((LISTEN+=1))
            rlFileRestore --namespace port_wildcard
            rlRun "service sshd restart"
            # Rate limit service restarts by sleeping
            rlRun "sleep 3s"
        rlPhaseEnd
    fi

    if ! rlIsRHEL '<7.3'; then
        rlPhaseStartTest "PermitOpen with host wildcard and specific port"
            rlFileBackup --namespace host_wildcard /etc/ssh/sshd_config /etc/hosts
            rlRun "echo 'PermitOpen *:$LISTEN' >>/etc/ssh/sshd_config"
            rlRun "echo '$IP wildhost1 wildhost2' >>/etc/hosts"
            rlRun "service sshd restart"
            # Rate limit service restarts by sleeping
            rlRun "sleep 3s"
            forwarding_test "success" $FORWARDED wildhost1 $LISTEN
            ((FORWARDED+=1))
            forwarding_test "success" $FORWARDED wildhost2 $LISTEN
            ((FORWARDED+=1))
            ((LISTEN+=1)) # different listen port, should fail
            forwarding_test "failure" $FORWARDED wildhost2 $LISTEN
            rlFileRestore --namespace host_wildcard
        rlPhaseEnd
    fi

    rlPhaseStartCleanup
        rlRun "userdel -rf $USER"
        rlRun "popd"
        rlFileRestore
        rlServiceRestore sshd
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        # Collect journal data.  If the test fails, the log probably
        # explains why, which may be difficult to determine without logs.
        rlRun "journalctl -b 0 > '$TMT_TEST_DATA'/journalctl.txt"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
