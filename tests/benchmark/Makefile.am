#
# tests/benchmark/Makefile.am
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

AM_CFLAGS = -I$(srcdir)/../../include -O2 -DNDEBUG

noinst_PROGRAMS = open-bench vc vc-scan 

vc_SOURCES = ../../clients/vc-quiet.c ../../clients/vc.h ../../clients/vc-lib.c ../../clients/talpa.c
vc_scan_CFLAGS =-DSCANFILE $(AM_CFLAGS)
vc_scan_SOURCES = ../../clients/vc-quiet.c ../../clients/vc.h ../../clients/vc-lib.c ../../clients/talpa.c


benchmark: open-bench vc vc-scan
	@./bench.sh
