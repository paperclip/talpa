#! /usr/bin/perl


use GD::Graph::lines;

use strict;

our $nr_cpus;
our $kernel;
our $open_loops;
our $test_runs;

our $gx = 700;
our $gy = 500;

our %results;

sub parse_stdin
{
    while ( <> ) {
        chomp $_;
        if ( /^System CPUs:\s+(\d+)/ ) {
            $nr_cpus = $1;
            last;
        }
    }

    while ( <> ) {
        chomp $_;
        if ( /^Kernel detected:\s+(.+)/ ) {
            $kernel = $1;
            last;
        }
    }

    while ( <> ) {
        chomp $_;
        if ( /^Open loops:\s+(\d+)/ ) {
            $open_loops = $1;
            last;
        }
    }

    while ( <> ) {
        chomp $_;
        if ( /^Test runs:\s+(\d+)/ ) {
            $test_runs = $1;
            last;
        }
    }

    my $test;
    my $openers = 0;
    my @ares;
    my $res;
    my $tot;
    my $cnt;
    my %results;
    my @subtest;
    my $interceptor;

    while ( <> ) {
        chomp $_;

        if ( /^(\w+.*):$/ ) {
            if ( $tot > 0 && $cnt > 0 ) {
#                 print "### $tot / $cnt\n";
                $tot /= $cnt;
                push @subtest, $tot;
            }
            $tot = 0;
            $cnt = 0;
            if ( not $test eq "" ) {
                $results{$test} = join " ", @subtest;
                undef @subtest;
            }
            $test = $1;
            if ( $test =~ /(Interceptor.*?)\s+\((\w+)\)/ ) {
                $interceptor = $2;
                $test = "$1 [$2]";
            } elsif ( not $interceptor eq "" ) {
                $test = "$test [$interceptor]";
            }
#             print "$test\n";
            $openers = 0;
            next;
        }

        if ( /\s+(\d+)\s+openers?:/ ) {
            if ( $tot > 0 && $cnt > 0 ) {
#                 print "### $tot / $cnt\n";
                $tot /= $cnt;
                push @subtest, $tot;
            }
            $tot = 0;
            $cnt = 0;
            $openers = $1;
            next;
        }

        next if $openers == 0;

        @ares = split " ", $_;
        my $subtot = 0;
        foreach $res (@ares) {
            if ( $res =~ /(\d+.\d{1,3})-\[(\d+.\d{1,3})\/(\d+.\d{1,3})/ ) {
                my $ops;
                my $time = $1;

                if ( $test =~ /scan/ )
                {
                    $ops = ($open_loops/10) / $time;
                }
                else
                {
                    $ops = $open_loops / $time;
                }
#                 print "--- $1 $ops\n";
                $subtot += $ops;
            }
        }

        if ( $subtot > 0 ) {
#             print "ops: $subtot\n";
            $cnt++;
            $tot += $subtot;
        }
    }

    if ( $tot > 0 && $cnt > 0 ) {
        $tot /= $cnt;
        push @subtest, $tot;
    }
    $results{$test} = join " ", @subtest;

    return %results;
}

sub draw_graph
{
    my $filename = shift;
    my $title = shift;

    my $test;
    my @tests;

    while ( my $testkey = shift @_ ) {
        foreach $test (sort keys %results) {
            if ( $test =~ /$testkey/ ) {
                push @tests, $test;
            }
        }
    }

    my @data;
    my @values;
    my $omax = 0;

    $data[0] = "";

    foreach $test (@tests) {
        @values = split " ", $results{$test};
# print "$test: $results{$test}\n";
        push @data, [ @values ];
        my $openers = $#values + 1;
        $omax = $openers if $openers > $omax;
    }

    return unless $omax > 0;

    my $xlegend;
    for ( my $i = 0; $i < $omax; $i++ ) {
        $xlegend .= 1<<$i;
        $xlegend .= ' ';
# print "$xlegend\n";
    }
    $data[0] = [ split " ", $xlegend ];

# print "$data[0]\n";
# print "$data[1]\n";
# print "$data[2]\n";


    my $graph = GD::Graph::lines->new($gx, $gy + $#data*20) or die;

    $graph->set(
        x_label           => 'Number of opener processes',
        y_label           => 'Total opens/sec',
        title             => $title,
        transparent       => 0,
        interlaced        => 0,
        line_width        => 2,
        t_margin          => 10,
        b_margin          => 10,
        l_margin          => 10,
        r_margin          => 10,
#        y_max_value       => 500000,
#        y_min_value       => 0
    ) or die;

    $graph->set_legend(@tests);

    my $gd = $graph->plot(\@data) or die;

    open IMG, ">$filename" or die;
    print IMG $gd->png;
    close IMG;
}

%results = parse_stdin();


foreach my $test (keys %results) {
    print "$test: $results{$test}\n";
}


draw_graph('cache-scaling.png', 'Cache scaling', 'cache');
draw_graph('clean-vs-cache.png', 'Clean kernel vs. cached interception', 'Clean kernel', 'cache');
draw_graph('clean-vs-intercepting.png', 'Clean kernel vs. intercepting', 'Clean kernel', 'Hooked', 'Interceptor loaded', 'Interceptor enabled');
draw_graph('clean-vs-syscallhook.png', 'Clean kernel vs. syscallhook', 'Clean kernel', 'Hooked');
draw_graph('interceptors.png', 'Interceptor vs. interceptor', 'Interceptor loaded', 'Interceptor enabled');
draw_graph('userspace-round-trip.png', 'Userspace round trip', 'vetting client.? \[');
draw_graph('scan-64k.png', 'Scan first 64k in 4k chunks', 'scan');
draw_graph('filters.png', 'Filter status', 'Interceptor enabled', 'Filter');

