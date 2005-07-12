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

${srcdir}/tlp-cleanup.sh

insmod modules/tlp-denysyslog.${ko}

./tlp-2-023 "Standard interceptor processor failure while opening /bin/bash on behalf of process tlp-2-023[" 1 1
./tlp-2-023 "Unexpected pass through action request while opening /bin/bash on behalf of process tlp-2-023[" 1 2
./tlp-2-023 "Unexpected allow action request while opening /bin/bash on behalf of process tlp-2-023[" 1 3
./tlp-2-023 "Access denied while opening /bin/bash on behalf of process tlp-2-023[" 1 4
./tlp-2-023 "Timeout occured while opening /bin/bash on behalf of process tlp-2-023[" 1 5
./tlp-2-023 "Error occured while opening /bin/bash on behalf of process tlp-2-023[" 1 6

./tlp-2-023 "Standard interceptor processor failure while closing /bin/bash on behalf of process tlp-2-023[" 2 1
./tlp-2-023 "Unexpected pass through action request while closing /bin/bash on behalf of process tlp-2-023[" 2 2
./tlp-2-023 "Unexpected allow action request while closing /bin/bash on behalf of process tlp-2-023[" 2 3
./tlp-2-023 "Access denied while closing /bin/bash on behalf of process tlp-2-023[" 2 4
./tlp-2-023 "Timeout occured while closing /bin/bash on behalf of process tlp-2-023[" 2 5
./tlp-2-023 "Error occured while closing /bin/bash on behalf of process tlp-2-023[" 2 6

./tlp-2-023 "Standard interceptor processor failure while executing /bin/bash on behalf of process tlp-2-023[" 3 1
./tlp-2-023 "Unexpected pass through action request while executing /bin/bash on behalf of process tlp-2-023[" 3 2
./tlp-2-023 "Unexpected allow action request while executing /bin/bash on behalf of process tlp-2-023[" 3 3
./tlp-2-023 "Access denied while executing /bin/bash on behalf of process tlp-2-023[" 3 4
./tlp-2-023 "Timeout occured while executing /bin/bash on behalf of process tlp-2-023[" 3 5
./tlp-2-023 "Error occured while executing /bin/bash on behalf of process tlp-2-023[" 3 6

exit 0
