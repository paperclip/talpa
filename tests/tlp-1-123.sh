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

. ${srcdir}/talpa-init.sh

tmpdir='/tmp/tlp-test'

fs=ext2
mkfs='/sbin/mkfs.ext2'
if [ ! -x "$mkfs" ]; then
    exit 77
fi

mkdir -p ${tmpdir}/mnt1
dd if=/dev/zero of=${tmpdir}/fs1.img bs=1M count=4 >/dev/null 2>&1
${mkfs} -q -F ${tmpdir}/fs1.img >/dev/null
mount -t $fs ${tmpdir}/fs1.img ${tmpdir}/mnt1 -o loop
touch ${tmpdir}/mnt1/file

lsattr ${tmpdir}/mnt1/file >/dev/null || { echo "Error on first access!"; exit 1; }
talpa_disable
talpa_unload
lsattr ${tmpdir}/mnt1/file >/dev/null || { echo "Error on second access!"; exit 2; }

umount ${tmpdir}/mnt1

exit 0
