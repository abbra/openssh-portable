# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Makefile of /CoreOS/openssh/Sanity/pam_ssh_agent_auth
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

export TEST=/CoreOS/openssh/Sanity/pam_ssh_agent_auth
export TESTVERSION=1.0

BUILT_FILES=

FILES=$(METADATA) runtest.sh Makefile pam_save_ssh_var.c

.PHONY: all install download clean

run: $(FILES) build
	./runtest.sh

build: $(BUILT_FILES)
	test -x runtest.sh || chmod a+x runtest.sh

clean:
	rm -f *~ $(BUILT_FILES)


-include /usr/share/rhts/lib/rhts-make.include

$(METADATA): Makefile
	@echo "Owner:           Jakub Jelen <jjelen@redhat.com>" > $(METADATA)
	@echo "Name:            $(TEST)" >> $(METADATA)
	@echo "TestVersion:     $(TESTVERSION)" >> $(METADATA)
	@echo "Path:            $(TEST_DIR)" >> $(METADATA)
	@echo "Description:     This is basic sanity test for pam_ssh_agent_auth" >> $(METADATA)
	@echo "Type:            Sanity" >> $(METADATA)
	@echo "TestTime:        5m" >> $(METADATA)
	@echo "RunFor:          openssh" >> $(METADATA)
	@echo "Requires:        openssh pam_ssh_agent_auth pam-devel expect" >> $(METADATA)
	@echo "RhtsRequires:    library(distribution/fips)" >> $(METADATA)
	@echo "Priority:        Normal" >> $(METADATA)
	@echo "License:         GPLv2+" >> $(METADATA)
	@echo "Confidential:    no" >> $(METADATA)
	@echo "Destructive:     no" >> $(METADATA)
	@echo "Releases:        -RHEL4 -RHELClient5 -RHELServer5" >> $(METADATA)

	rhts-lint $(METADATA)
