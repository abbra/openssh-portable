#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/openssh/Sanity/pam_ssh_agent_auth
#   Description: This is a basic sanity test for pam_ssh_agent_auth
#   Author: Jakub Jelen <jjelen@redhat.com>
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
PAM_SUDO="/etc/pam.d/sudo"
PAM_SSHD="/etc/pam.d/sshd"
PAM_MODULE="pam_save_ssh_var"
SUDOERS_CFG="/etc/sudoers.d/01_pam_ssh_auth"
SSHD_CFG="/etc/ssh/sshd_config"
USER="testuser$RANDOM"
PASS="testpassxy4re.3298fhdsaf"
AUTH_KEYS="/etc/security/authorized_keys"
AK_COMMAND_BIN="/root/ak.sh"
AK_COMMAND_KEYS="/root/akeys"
declare -a KEYS=("rsa" "ecdsa")

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm $PACKAGE
        rlAssertRpm pam_ssh_agent_auth
        rlImport distribution/fips
        rlServiceStart sshd
        # The following line is a temporary fix for https://pagure.io/releng/issue/12187
        rlRun "rpm --restore filesystem"
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "cp ${PAM_MODULE}.c $TmpDir/"
        rlRun "pushd $TmpDir"
        rlFileBackup --clean $PAM_SUDO /etc/sudoers /etc/sudoers.d/ /etc/security/ $AUTH_KEYS
        rlRun "sed -i '1 a\
auth       sufficient   pam_ssh_agent_auth.so file=$AUTH_KEYS' $PAM_SUDO"
        rlRun "echo 'Defaults    env_keep += \"SSH_AUTH_SOCK\"' > $SUDOERS_CFG"
        rlRun "echo 'Defaults    !requiretty' >> $SUDOERS_CFG"
        grep '^%wheel' /etc/sudoers || \
           rlRun "echo '%wheel        ALL=(ALL)       ALL' >> $SUDOERS_CFG"
        rlRun "useradd $USER -G wheel"
        rlRun "echo $PASS |passwd --stdin $USER"
    rlPhaseEnd

    for KEY in "${KEYS[@]}"; do
        rlPhaseStartTest "Test with key type $KEY"
            rlRun "su $USER -c 'ssh-keygen -t $KEY -f ~/.ssh/my_id_$KEY -N \"\"'" 0

            # Without authorized_keys, the authentication should fail
            rlRun -s "su $USER -c 'eval \`ssh-agent\`; sudo id; ssh-agent -k'" 0
            rlAssertNotGrep "uid=0(root) gid=0(root)" $rlRun_LOG

            # Append the keys only to make sure we can match also the non-first line
            rlRun "cat ~$USER/.ssh/my_id_${KEY}.pub >> $AUTH_KEYS"
            rlRun -s "su $USER -c 'eval \`ssh-agent\`; ssh-add ~/.ssh/my_id_$KEY; sudo id; ssh-agent -k'"
            rlAssertGrep "uid=0(root) gid=0(root)" $rlRun_LOG
        rlPhaseEnd
    done

    if rlIsRHEL '<6.8' || ( rlIsRHEL '<7.3' && rlIsRHEL 7 ) ; then
        : # not available
    else
        rlPhaseStartSetup "Setup for authorized_keys_command"
            rlFileBackup --namespace ak_command $PAM_SUDO
            rlRun "rm -f $AUTH_KEYS"
            cat >$AK_COMMAND_BIN <<_EOF
#!/bin/bash
cat $AK_COMMAND_KEYS
_EOF
            rlRun "chmod +x $AK_COMMAND_BIN"
            rlRun "sed -i 's|.*pam_ssh_agent_auth.*|auth sufficient pam_ssh_agent_auth.so authorized_keys_command=$AK_COMMAND_BIN authorized_keys_command_user=root|' $PAM_SUDO"
            rlRun "cat $PAM_SUDO"
        rlPhaseEnd

        for KEY in "${KEYS[@]}"; do
            rlPhaseStartTest "Test authorized_keys_command with key type $KEY (bz1299555, bz1317858)"
                rlRun "cat ~$USER/.ssh/my_id_${KEY}.pub >$AK_COMMAND_KEYS"
                rlRun -s "su $USER -c 'eval \`ssh-agent\`; ssh-add ~/.ssh/my_id_$KEY; sudo id; ssh-agent -k'"
                rlAssertGrep "uid=0(root) gid=0(root)" $rlRun_LOG
            rlPhaseEnd
        done

        rlPhaseStartCleanup "Cleanup for authorized_keys_command"
            rlFileRestore --namespace ak_command
            rlRun "rm -f $AK_COMMAND_BIN $AK_COMMAND_KEYS"
        rlPhaseEnd
    fi

    if rlIsRHEL '>=7.3'; then # not in Fedora anymore
        rlPhaseStartTest "bz1312304 - Exposing information about succesful auth"
            rlRun "rlFileBackup --namespace exposing $PAM_SSHD"
            rlRun "rlFileBackup --namespace exposing $SSHD_CFG"
            rlRun "rlFileBackup --namespace exposing /root/.ssh/"
            rlRun "rm -f ~/.ssh/id_rsa*"
            rlRun "ssh-keygen -f ~/.ssh/id_rsa -N \"\"" 0
            rlRun "ssh-keyscan localhost >~/.ssh/known_hosts" 0
            USER_AK_FILE=~$USER/.ssh/authorized_keys
            rlRun "cat ~/.ssh/id_rsa.pub >$USER_AK_FILE"
            rlRun "chown $USER:$USER $USER_AK_FILE"
            rlRun "chmod 0600 $USER_AK_FILE"
            rlRun "gcc -fPIC -DPIC -shared -rdynamic -o $PAM_MODULE.o $PAM_MODULE.c"
            rlRun "test -d /lib64/security && cp $PAM_MODULE.o /lib64/security/" 0,1
            rlRun "test -d /lib/security && cp $PAM_MODULE.o /lib/security/" 0,1
            rlRun "sed -i '1 i auth       optional         $PAM_MODULE.o' $PAM_SSHD"

            # pam-and-env should expose information to both PAM and environmental variable;
            # we will be testing only env variable here for the time being,
            rlRun "echo 'ExposeAuthenticationMethods pam-and-env' >>$SSHD_CFG"
            rlRun "sed -i '/^ChallengeResponseAuthentication/ d' $SSHD_CFG"
            rlRun "service sshd restart"
            rlWaitForSocket 22 -t 5
            rlRun -s "ssh -i ~/.ssh/id_rsa $USER@localhost \"env|grep SSH_USER_AUTH\"" 0 \
                "Environment variable SSH_USER_AUTH is set"
            rlAssertGrep "^SSH_USER_AUTH=publickey:" $rlRun_LOG
            rlRun "rm -f $rlRun_LOG"

            # pam-only should expose information only to PAM and not to environment variable
            rlRun "sed -i 's/pam-and-env/pam-only/' $SSHD_CFG"
            rlRun "echo 'AuthenticationMethods publickey,keyboard-interactive:pam' >>$SSHD_CFG"
            rlRun "service sshd restart"
            rlWaitForSocket 22 -t 5
ssh_with_pass() {
    ssh_args=("-i /root/.ssh/id_rsa")
    ssh_args+=("$USER@localhost")
    cat >ssh.exp <<_EOF
#!/usr/bin/expect -f

set timeout 5
spawn ssh ${ssh_args[*]} "echo CONNECTED; env|grep SSH_USER_AUTH"
expect {
    -re {.*[Pp]assword.*} { send -- "$PASS\r"; exp_continue }
    timeout { exit 1 }
    eof { exit 0 }
}
_EOF
    rlRun -s "expect -f ssh.exp"
}
            #rlRun -s "ssh ${ssh_args[*]} \"echo CONNECTED; env|grep SSH_USER_AUTH\"" 1 \
                #"Environment variable SSH_USER_AUTH is NOT set"
            rlRun "ssh_with_pass"
            rlRun "grep -q CONNECTED $rlRun_LOG" 0 "Connection was successful"
            rlAssertGrep "^SSH_USER_AUTH: 'publickey:" /tmp/SSH_USER_AUTH
            rlRun "cat /tmp/SSH_USER_AUTH"
            rlRun "rm -f $rlRun_LOG /tmp/SSH_USER_AUTH"
            for pm in /lib64/security/$PAM_MODULE.o /lib/security/$PAM_MODULE.o; do
                rlRun "test -e $pm && rm -f $pm" 0,1
            done
            rlRun "rlFileRestore --namespace exposing"
        rlPhaseEnd
    fi

    rlPhaseStartCleanup
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlRun "userdel -fr $USER"
        rlFileRestore
        rlServiceRestore sshd
        # Collect journal data.  If the test fails, the log probably
        # explains why, which may be difficult to determine without logs.
        rlRun "journalctl -b 0 > '$TMT_TEST_DATA'/journalctl.txt"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
