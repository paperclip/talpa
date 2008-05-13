#
# talpa-syscallhookprobe/Makefile.am
#
# TALPA Filesystem Interceptor
#
# Copyright (C) 2008 Sophos Plc, Oxford, England.
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

include src/platforms/linux/talpa_syscallhookprobe/common.mk

talpa_syscallhookprobe_o_SOURCES =  $(talpaSyscallHookProbeSOURCES)

talpa_syscallhookprobe_o_CFLAGS  =  $(modules_CFLAGS)
talpa_syscallhookprobe_o_LINK    =  $(MODULELINKCMD)

TALPAMODULESRC += $(talpa_syscallhookprobe_o_SOURCES)
#
# End of talpa-syscallhookprobe/Makefile.am
#
