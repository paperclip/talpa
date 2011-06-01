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

if test -f ${talpafs}/interceptors/${interceptor_name}/status; then
    echo disable >${talpafs}/interceptors/${interceptor_name}/status 2>/dev/null
    sync
fi

rmmod talpa_${interceptor_module} 2>/dev/null
rmmod talpa_pedconnector 2>/dev/null
rmmod talpa_vcdevice 2>/dev/null
rmmod talpa_core 2>/dev/null

tlp_insmod ../talpa_core.${ko}
tlp_insmod ../talpa_vcdevice.${ko}
tlp_insmod ../talpa_pedconnector.${ko}
tlp_insmod ../talpa_${interceptor_module}.${ko}

echo disable >${talpafs}/intercept-filters/DebugSyslog/status
echo +proc >${talpafs}/intercept-filters/FilesystemExclusionProcessor/fstypes
echo /tmp/tlp-test/ >${talpafs}/intercept-filters/FilesystemInclusionProcessor/include-path
echo enable >${talpafs}/intercept-filters/FilesystemInclusionProcessor/status
echo enable >${talpafs}/intercept-filters/ProcessExclusionProcessor/status
echo enable >${talpafs}/intercept-filters/Cache/status
echo enable >${talpafs}/intercept-filters/DegradedModeProcessor/status
echo enable >${talpafs}/interceptors/${interceptor_name}/status

./tlp-4-003a &

sleep 1

exit 0
