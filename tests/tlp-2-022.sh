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

tlp_insmod modules/tlp-denysyslog.${ko}

testproc=intercept-filters/DenySyslog/
testvar=status

procpath=${talpafs}/${testproc}/${testvar}
read <${procpath} status1
echo garbage >${procpath}
read <${procpath} status2
if test "$status1" != "$status2"; then
    exit 1
fi

dd if=/dev/urandom of=${procpath} bs=1 count=100000 2>/dev/null
read <${procpath} status3
if test "$status1" != "$status3"; then
    exit 1
fi

exit 0
