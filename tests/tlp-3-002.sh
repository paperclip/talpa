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

. ${srcdir}/functions.sh

${srcdir}/tlp-cleanup.sh

get_mount_fs /

insmod modules/tlp-exclusion.${ko}
echo -n "-dir" >/proc/sys/talpa/intercept-filters/FilesystemExclusionProcessor/specials
./tlp-3-001 /bin ${_mount_fs} 2

exit $?
