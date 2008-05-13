#! /bin/bash
#
# TALPA test script
#
# Copyright (C) 2008 Sophos Plc, Oxford, England.
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

if test "$interceptor_module" = "syscall"; then
    tlp_insmod ../talpa_syscallhook.${ko}
elif test "$interceptor_module" = "vfshook"; then
    tlp_insmod ../talpa_syscallhook.${ko} hook_mask=mu
else
    exit 77
fi

tlp_insmod modules/tlp-syscalltable.${ko}
if test $? -ne 0; then
    exit 1
fi

(date +%s >/tmp/tlp-9-003-1.tmp && rmmod talpa_syscallhook && date +%s >/tmp/tlp-9-003-2.tmp) &

sleep 1
rmmod tlp_syscalltable
wait

if test ! -f /tmp/tlp-9-003-2.tmp; then
    exit 1
fi

read start </tmp/tlp-9-003-1.tmp
read finish </tmp/tlp-9-003-2.tmp

if test $finish -eq $start; then
    exit 1
fi

exit 0
