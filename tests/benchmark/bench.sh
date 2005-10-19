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

bash="/bin/bash"
insmod="/sbin/insmod"
rmmod="/sbin/rmmod"

openclose="./open-bench"

open_file="/bin/ls"
open_loops=1000
nr_runs=1
nr_cpus=`grep "processor" /proc/cpuinfo | wc -l`

if grep "Linux version 2.6." /proc/version >/dev/null; then
    kernel=2.6
    ko=ko
    interceptors="vfshook lsm"
else
    kernel=2.4
    ko=o
    interceptors="syscall"
fi

function talpa_conf_filters()
{
    l=/proc/sys/talpa/intercept-filters/*

    for i in $l; do
        if [ $i = "/proc/sys/talpa/intercept-filters/DebugSyslog" ]; then
            continue
        fi
        if [ -d $i ]; then
            echo $2 >$i/$1 2>/dev/null
        fi
    done
}

function talpa_conf_interceptors()
{
    l=/proc/sys/talpa/interceptors/*

    for i in $l; do
        if [ -d $i ]; then
            echo $2 >$i/$1 2>/dev/null
        fi
    done
}

function talpa_enable_interceptors()
{
    talpa_conf_interceptors status enable
}

function talpa_disable_interceptors()
{
    talpa_conf_interceptors status disable
}

function talpa_no_close_interception()
{
    talpa_conf_interceptors ops -close
}

function talpa_unload()
{
    talpa_disable_interceptors

    $rmmod talpa_syscall 2>/dev/null
    $rmmod talpa_lsm 2>/dev/null
    $rmmod talpa_vfshook 2>/dev/null
    $rmmod talpa_syscallhook 2>/dev/null
    $rmmod talpa_pedconnector 2>/dev/null
    $rmmod talpa_pedevice 2>/dev/null
    $rmmod talpa_vcdevice 2>/dev/null
    $rmmod talpa_core 2>/dev/null
    $rmmod talpa_linux 2>/dev/null
}

function talpa_load_core()
{
    $insmod ../../talpa_linux.$ko
    $insmod ../../talpa_core.$ko
    $insmod ../../talpa_vcdevice.$ko
    $insmod ../../talpa_pedevice.$ko
}

function open_close()
{
    local nr

    nr=$1
    es=""
    run=$nr_runs

    while [ $nr -gt 0 ]; do
        es="$es $openclose -f$open_file -l$open_loops &"
        let nr=($nr)-1
    done

    if [ $spawn -eq 1 ]; then
        echo -e "\t$spawn opener:"
    else
        echo -e "\t$spawn openers:"
    fi

    while [ $run -gt 0 ]; do
        res=`$bash -c "$es"`
        echo -en "\t\t"
        echo $res
        let run=($run)-1
    done
}

function open_close_test()
{
    local spawn

    echo "$1:"

    let spawn=1
    open_close $spawn

    let spawn=($nr_cpus)/2
    if [ $spawn -gt 1 ]; then
        open_close $spawn
    fi

    let spawn=$nr_cpus
    if [ $spawn -gt 1 ]; then
        open_close $spawn
    fi

    let spawn=($nr_cpus)*2
    if [ $spawn -gt 1 ]; then
        open_close $spawn
    fi
}

function run_vetting_clients()
{
    nr=$2

    while [ $nr -gt 0 ]; do
        $1 >/dev/null &
        let nr=($nr)-1
    done
}

function kill_vetting_clients()
{
    killall -INT vc 2>/dev/null
    killall -INT vc-scan 2>/dev/null
}

function vetting_test()
{
    local spawn
    local extra
    local fs
    local vc

    vc=./vc

    if [ $# -gt 0 ]; then
        if [ $1 = "cache" ]; then
            extra=", cache enabled"
            fs=`stat -f $open_file | grep "Type:" | cut -d ':' -f 4 | cut -d ' ' -f 2`
            echo enable >/proc/sys/talpa/intercept-filters/Cache/status
            echo "+$fs" >/proc/sys/talpa/intercept-filters/Cache/fstypes
        fi
    fi

    let spawn=1
    run_vetting_clients $vc $spawn
    open_close_test "$spawn vetting client$extra"
    kill_vetting_clients

    let spawn=($nr_cpus)/2
    if [ $spawn -gt 1 ]; then
        run_vetting_clients $vc $spawn
        open_close_test "$spawn vetting clients$extra"
        kill_vetting_clients
    fi

    let spawn=$nr_cpus
    if [ $spawn -gt 1 ]; then
        run_vetting_clients $vc $spawn
        open_close_test "$spawn vetting clients$extra"
        kill_vetting_clients
    fi

    let spawn=($nr_cpus)*2
    if [ $spawn -gt 1 ]; then
        run_vetting_clients $vc $spawn
        open_close_test "$spawn vetting clients$extra"
        kill_vetting_clients
    fi
}

echo "System CPUs: $nr_cpus"
echo "Kernel detected: $kernel"

talpa_unload
open_close_test "Clean kernel"
talpa_load_core

for interceptor in $interceptors; do

    if [ $interceptor = "syscall" -o $interceptor = "vfshook" ]; then
        if [ $interceptor = "syscall" ]; then
            $insmod ../../talpa_syscallhook.$ko
        fi
        if [ $interceptor = "vfshook" ]; then
            $insmod ../../talpa_syscallhook.$ko hook_mask=mu
        fi

        open_close_test "Hooked kernel"
    fi

    $insmod ../../talpa_$interceptor.$ko
    talpa_no_close_interception

    open_close_test "Interceptor loaded ($interceptor)"

    talpa_enable_interceptors
    open_close_test "Interceptor enabled ($interceptor), filters default"

    vetting_test

    vetting_test "cache"

    talpa_conf_filters status disable
    open_close_test "Filters disabled"

    talpa_conf_filters status enable
    open_close_test "Filters enabled"

    talpa_disable_interceptors
    $rmmod talpa_$interceptor.$ko

done

talpa_unload

exit 0
