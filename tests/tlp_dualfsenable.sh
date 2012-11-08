#! /bin/bash
#
# TALPA test script
#
# Copyright (C) 2004-2011 Sophos Limited, Oxford, England.
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

inc=1
rc=1

function testone
{
    if [ "$1" = "yes" ]; then
        . ${srcdir}/tlp-cleanup.sh

        tlp_insmod modules/tlp-${2}.${ko}

        testproc=intercept-processors/${3}/
        testvar=status
        testval=enable
        testres=enabled

        testpath=${talpafs}/${testproc}/${testvar}

        echo ${testval} >${testpath}
        status=`cat ${testpath}`
        if test "$status" != "$testres"; then
            exit $inc
        fi

        let inc=($inc)+1
        rc=0
    fi
}

tlp_insmod ../talpa_linux.${ko} || exit 1
tlp_insmod ../talpa_core.${ko} || exit 1
rmmod talpa_core >/dev/null 2>&1
rmmod talpa_linux >/dev/null 2>&1

procfs=$talpaprocfs
securityfs=$talpasecurityfs
dualfs=$talpadualfs

testone $procfs procfs ProcfsTest
testone $securityfs securityfs SecurityfsTest
testone $dualfs dualfs DualfsTest

exit $rc
