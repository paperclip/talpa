#! /usr/bin/perl

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

use strict;
use integer;

my $test_path = '/usr';

sub detect_cpus
{
    my $cnt;
    open(FILE,"/proc/cpuinfo") or die;
    while ( <FILE> ) {
        $cnt++ if /^processor\s+:\s+/;
    }
    close(FILE);
    return $cnt;
}

sub get_ram_stats
{
    my ( $free, $buffers, $cache, $active, $inactive, $swapped, $swapcache );
    open(FILE,"/proc/meminfo") or die;
    while ( <FILE> ) {
        if ( /^MemFree:\s+(\d+)\s+/ ) {
            $free = 0 + $1;
        } elsif ( /^Buffers:\s+(\d+)\s+/ ) {
            $buffers = 0 + $1;
        } elsif ( /^Cached:\s+(\d+)\s+/ ) {
            $cache = 0 + $1;
        } elsif ( /^Active:\s+(\d+)\s+/ ) {
            $active = 0 + $1;
        } elsif ( /^Inactive:\s+(\d+)\s+/ ) {
            $inactive = 0 + $1;
        } elsif ( /^SwapTotal:\s+(\d+)\s+/ ) {
            $swapped = 0 + $1;
        } elsif ( /^SwapCached:\s+(\d+)\s+/ ) {
            $swapcache = 0 + $1;
        }
    }
    close(FILE);
    return ( $free, $buffers, $cache, $active, $inactive, $swapped, $swapcache );
}

my $cpus = detect_cpus();
my $tortures = $cpus * 2;
print "$cpus CPUs detected, will spawn $tortures tortures.\n";
my @meminfo1 = get_ram_stats();
print "Memory usage summary:\n(before)\tFree: $meminfo1[0]  Buffers: $meminfo1[1]  Cache: $meminfo1[2]  Active: $meminfo1[3]  Inactive: $meminfo1[4]  Swap: $meminfo1[5]  SwapCache: $meminfo1[6]\n";
my @child;
for ( my $cnt = 0; $cnt < $tortures; $cnt++ ) {
    $child[$cnt] = fork();
    die unless defined $child[$cnt];
    if ( $child[$cnt] == 0 ) {
        system("find ${test_path} -xdev -type f -exec dd 2>/dev/null if={} of=/dev/null bs=1 count=1 \\;");
        exit 0;
    }
}
waitpid -1, 0;
my @meminfo2 = get_ram_stats();
print "(after) \tFree: $meminfo2[0]  Buffers: $meminfo2[1]  Cache: $meminfo2[2]  Active: $meminfo2[3]  Inactive: $meminfo2[4]  Swap: $meminfo2[5]  SwapCache: $meminfo2[6]\n";
my @meminfo3;
my $cnt;
foreach my $value ( @meminfo1 ) {
    $meminfo3[$cnt] = $meminfo2[$cnt] - $meminfo1[$cnt];
    $cnt++;
}
print "(delta) \tFree: $meminfo3[0]  Buffers: $meminfo3[1]  Cache: $meminfo3[2]  Active: $meminfo3[3]  Inactive: $meminfo3[4]  Swap: $meminfo3[5]  SwapCache: $meminfo3[6]\n";

0;
