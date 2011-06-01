#
# talpa-linux/Makefile.am
#
# TALPA Filesystem Interceptor
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

include src/app-ctrl/core/talpa-linux/common.mk

talpa_linux_o_SOURCES    =  $(talpaLinuxSOURCES)

talpa_linux_o_CFLAGS     =   $(modules_CFLAGS)
talpa_linux_o_LINK       =   $(MODULELINKCMD)

TALPAMODULESRC += $(talpa_linux_o_SOURCES) $(talpaSecurityFSConfiguratorSOURCES) $(talpaProcFSConfiguratorSOURCES) $(talpaDualFSConfiguratorSources)

if BUILDSECURITYFS
talpa_linux_o_SOURCES += $(talpaSecurityFSConfiguratorSOURCES)
else !BUILDSECURITYFS
talpa_linux_o_SOURCES += $(talpaProcFSConfiguratorSOURCES)
endif !BUILDSECURITYFS

if BUILDDUALFS
talpa_linux_o_SOURCES += $(talpaDualFSConfiguratorSOURCES)
talpa_linux_o_SOURCES += $(talpaProcFSConfiguratorSOURCES)
endif BUILDDUALFS

#
# End of talpa-linux/Makefile.am
#
