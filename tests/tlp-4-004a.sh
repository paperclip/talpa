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

exit 0
