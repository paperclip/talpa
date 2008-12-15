#! /bin/bash
#
# TALPA test script
#
# Copyright (C) 2004 Sophos Plc, Oxford, England.
#
# This program is free software; you can redistribute it and/or modify it under the terms of the
# GNU General Public License Version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not,
# write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
#

. ${srcdir}/tlp-cleanup.sh

if su -c /bin/true nobody; then
    rm -f /tmp/talpa-file-object-test-file 2>/dev/null
    tlp_insmod modules/tlp-file.${ko}
    chmod 555 tlp-6-029
    chown nobody tlp-6-029
    su -c ./tlp-6-029 nobody
    rc=$?
    if [ $rc -eq 0 ]; then
        exit 0
    elif [ $rc -eq 77 ]; then
        # Actual test case failure
        exit 1
    else
        # Ignore failures when test can't run
        exit 77
    fi
else
    exit 77
fi
