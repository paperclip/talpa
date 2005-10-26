#
# clients/Makefile.am
#
# TALPA Filesystem Interceptor
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

AM_CFLAGS = -I$(srcdir)/../include -I$(srcdir)/../src -O2 -DNDEBUG

noinst_PROGRAMS =   vc vc-quiet vc-deny vc-count vc-threaded vc-poll \
                    pe pecat


vc_SOURCES = vc.c vc.h vc-lib.c
vc_deny_SOURCES = vc-deny.c vc.h vc-lib.c
vc_quiet_SOURCES = vc-quiet.c vc.h vc-lib.c
vc_count_SOURCES = vc-count.c vc.h vc-lib.c
vc_threaded_SOURCES = vc-threaded.c vc.h vc-lib.c
vc_threaded_LDFLAGS = -lpthread
vc_poll_SOURCES = vc-poll.c vc.h vc-lib.c

vc_CFLAGS = ${CLIENTFLAGS} $(AM_CFLAGS)
vc_deny_CFLAGS = ${CLIENTFLAGS} $(AM_CFLAGS)
vc_quiet_CFLAGS = ${CLIENTFLAGS} $(AM_CFLAGS)
vc_count_CFLAGS = ${CLIENTFLAGS} $(AM_CFLAGS)
vc_threaded_CFLAGS = -D_REENTRANT ${CLIENTFLAGS} $(AM_CFLAGS)
vc_poll_CFLAGS = ${CLIENTFLAGS} $(AM_CFLAGS)

pe_SOURCES = pe.c pe.h pe-lib.c
pecat_SOURCES = pecat.c pe.h pe-lib.c
