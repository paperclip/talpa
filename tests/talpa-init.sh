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

tlp_insmod ../talpa_linux.${ko}
tlp_insmod ../talpa_core.${ko}
tlp_insmod ../talpa_vcdevice.${ko}
tlp_insmod ../talpa_pedevice.${ko}
tlp_insmod ../talpa_pedconnector.${ko}
if test "$interceptor_module" = "syscall"; then
    tlp_insmod ../talpa_syscallhook.${ko}
fi
if test "$interceptor_module" = "vfshook"; then
    tlp_insmod ../talpa_syscallhook.${ko} hook_mask=mu
fi
tlp_insmod ../talpa_${interceptor_module}.${ko}

echo disable >${talpafs}/intercept-filters/DebugSyslog/status
echo +proc >${talpafs}/intercept-filters/FilesystemExclusionProcessor/fstypes
mkdir -p /tmp/tlp-test
dd if=/dev/zero of=/tmp/tlp-test/file bs=1k count=128 1>/dev/null 2>&1
cp -a /bin/true /tmp/tlp-test/
cp -a /bin/bash /tmp/tlp-test/
cp -a ${srcdir}/test-script*.sh /tmp/tlp-test/
echo /tmp/tlp-test/ >${talpafs}/intercept-filters/FilesystemInclusionProcessor/include-path
echo enable >${talpafs}/intercept-filters/FilesystemInclusionProcessor/status
echo enable >${talpafs}/intercept-filters/ProcessExclusionProcessor/status
echo enable >${talpafs}/intercept-filters/Cache/status
echo enable >${talpafs}/intercept-filters/DegradedModeProcessor/status
echo enable >${talpafs}/interceptors/${interceptor_name}/status
