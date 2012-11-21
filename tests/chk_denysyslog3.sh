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

./chk_denysyslog3 "Standard interceptor processor failure while opening /bin/bash on behalf of process chk_denysyslog3[" 1 1
./chk_denysyslog3 "Unexpected pass through action request while opening /bin/bash on behalf of process chk_denysyslog3[" 1 2
./chk_denysyslog3 "Unexpected allow action request while opening /bin/bash on behalf of process chk_denysyslog3[" 1 3
./chk_denysyslog3 "Access denied while opening /bin/bash on behalf of process chk_denysyslog3[" 1 4
./chk_denysyslog3 "Timeout occured while opening /bin/bash on behalf of process chk_denysyslog3[" 1 5
./chk_denysyslog3 "Error occured while opening /bin/bash on behalf of process chk_denysyslog3[" 1 6

./chk_denysyslog3 "Standard interceptor processor failure while closing /bin/bash on behalf of process chk_denysyslog3[" 2 1
./chk_denysyslog3 "Unexpected pass through action request while closing /bin/bash on behalf of process chk_denysyslog3[" 2 2
./chk_denysyslog3 "Unexpected allow action request while closing /bin/bash on behalf of process chk_denysyslog3[" 2 3
./chk_denysyslog3 "Access denied while closing /bin/bash on behalf of process chk_denysyslog3[" 2 4
./chk_denysyslog3 "Timeout occured while closing /bin/bash on behalf of process chk_denysyslog3[" 2 5
./chk_denysyslog3 "Error occured while closing /bin/bash on behalf of process chk_denysyslog3[" 2 6

./chk_denysyslog3 "Standard interceptor processor failure while executing /bin/bash on behalf of process chk_denysyslog3[" 3 1
./chk_denysyslog3 "Unexpected pass through action request while executing /bin/bash on behalf of process chk_denysyslog3[" 3 2
./chk_denysyslog3 "Unexpected allow action request while executing /bin/bash on behalf of process chk_denysyslog3[" 3 3
./chk_denysyslog3 "Access denied while executing /bin/bash on behalf of process chk_denysyslog3[" 3 4
./chk_denysyslog3 "Timeout occured while executing /bin/bash on behalf of process chk_denysyslog3[" 3 5
./chk_denysyslog3 "Error occured while executing /bin/bash on behalf of process chk_denysyslog3[" 3 6

exit 0
