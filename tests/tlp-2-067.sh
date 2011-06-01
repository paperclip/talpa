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

. ${srcdir}/talpa-init.sh
get_mount_fs /tmp
echo /tmp/tlp-test/ >${talpafs}/intercept-filters/FilesystemInclusionProcessor/include-path
echo -${_mount_fs} >${talpafs}/intercept-filters/FilesystemExclusionProcessor/fstypes
echo +fs:${_mount_fs}:1 >${talpafs}/intercept-filters/VettingController/routing
./tlp-2-063 1 /tmp/tlp-test/file
res=$?

exit $res
