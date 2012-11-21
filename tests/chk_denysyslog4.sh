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

tlp_insmod modules/tlp-denysyslog.${ko}

./chk_denysyslog4 "Standard interceptor processor failure while mounting /dev/sda1 at /mnt (ext2) on behalf of process chk_denysyslog4[" 4 1
./chk_denysyslog4 "Unexpected pass through action request while mounting /dev/sda1 at /mnt (ext2) on behalf of process chk_denysyslog4[" 4 2
./chk_denysyslog4 "Unexpected allow action request while mounting /dev/sda1 at /mnt (ext2) on behalf of process chk_denysyslog4[" 4 3
./chk_denysyslog4 "Access denied while mounting /dev/sda1 at /mnt (ext2) on behalf of process chk_denysyslog4[" 4 4
./chk_denysyslog4 "Timeout occured while mounting /dev/sda1 at /mnt (ext2) on behalf of process chk_denysyslog4[" 4 5
./chk_denysyslog4 "Error occured while mounting /dev/sda1 at /mnt (ext2) on behalf of process chk_denysyslog4[" 4 6

# Commented out since reworked FilesystemInfo object does not support creating from fake data.
#./tlp-2-024 "Standard interceptor processor failure while unmounting /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 5 1
#./tlp-2-024 "Unexpected pass through action request while unmounting /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 5 2
#./tlp-2-024 "Unexpected allow action request while unmounting /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 5 3
#./tlp-2-024 "Access denied while unmounting /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 5 4
#./tlp-2-024 "Timeout occured while unmounting /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 5 5
#./tlp-2-024 "Error occured while unmounting /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 5 6
#./tlp-2-024 "Error occured while processing unsupported object type /dev/sda1 at /mnt (ext2) on behalf of process tlp-2-024[" 3 6

exit 0
