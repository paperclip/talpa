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

sync

if test -f /proc/sys/talpa/interceptors/${interceptor_name}/status; then
    echo disable >/proc/sys/talpa/interceptors/${interceptor_name}/status 2>/dev/null
    sync
fi

rmmod talpa_${interceptor_module} 2>/dev/null
if test "$interceptor_module" = "syscall" -o "$interceptor_module" = "vfshook"; then
    rmmod talpa_syscallhook 2>/dev/null
fi
rmmod talpa_pedevice 2>/dev/null
rmmod talpa_vcdevice 2>/dev/null
rmmod talpa_core 2>/dev/null
rmmod talpa_linux 2>/dev/null

rmmod tlp-personality 2>/dev/null
rmmod tlp-fileinfo 2>/dev/null
rmmod tlp-filesysteminfo 2>/dev/null
rmmod tlp-syslog 2>/dev/null
rmmod tlp-procfs 2>/dev/null
rmmod tlp-stdinterceptor 2>/dev/null
rmmod tlp-inclusion 2>/dev/null
rmmod tlp-opexcl 2>/dev/null
rmmod tlp-denysyslog 2>/dev/null
rmmod tlp-threadinfo 2>/dev/null
rmmod tlp-exclusion 2>/dev/null
rmmod tlp-ddvc 2>/dev/null
rmmod tlp-cache 2>/dev/null
rmmod tlp-cacheobj 2>/dev/null
rmmod tlp-degrmode 2>/dev/null
rmmod tlp-file 2>/dev/null

rm -rf /tmp/tlp-test 2>/dev/null

exit 0
