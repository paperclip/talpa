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

. ${srcdir}/functions.sh

talpa_disable
talpa_unload

# Wait for modules to unload
for i in 0 1 2 3 4 5 6 7 8 9
do
    if lsmod | grep 'talpa\|tlp'
    then
        sleep 0.2 || sleep 1
    else
        break
    fi
done

if [ -d /tmp/tlp-test ]
then
    LSOF=`which lsof 2>/dev/null`
    if [ -x "$LSOF" ]
    then
        lsof /tmp/tlp-test 2>/dev/null
    fi
    mount | grep /tmp/tlp-test
    [ -d /tmp/tlp-test/mnt1 ] && umount /tmp/tlp-test/mnt1 2>/dev/null
    [ -d /tmp/tlp-test/mnt2 ] && umount /tmp/tlp-test/mnt2 2>/dev/null
    rm -rf /tmp/tlp-test 2>/dev/null
fi
true
