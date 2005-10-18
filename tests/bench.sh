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

interceptor_name=VFSHookInterceptor
interceptor_module=vfshook
ko=ko

bash="/bin/bash"
insmod="/sbin/insmod"
rmmod="/sbin/rmmod"

openclose="./open-bench"

nr_cpus=`grep "processor" /proc/cpuinfo | wc -l`
nr_loops=30000
nr_runs=1

echo -e "System CPUs: $nr_cpus\n"


function talpa_unload()
{
    if test -f /proc/sys/talpa/interceptors/${interceptor_name}/status; then
        echo disable >/proc/sys/talpa/interceptors/${interceptor_name}/status 2>/dev/null
        sync
    fi

    $rmmod talpa_${interceptor_module} 2>/dev/null
    if test "$interceptor_module" = "syscall" -o "$interceptor_module" = "vfshook"; then
        $rmmod talpa_syscallhook 2>/dev/null
    fi
    $rmmod talpa_pedconnector 2>/dev/null
    $rmmod talpa_pedevice 2>/dev/null
    $rmmod talpa_vcdevice 2>/dev/null
    $rmmod talpa_core 2>/dev/null
    $rmmod talpa_linux 2>/dev/null
}

talpa_unload

$insmod talpa_linux.${ko}
$insmod talpa_core.${ko}
$insmod talpa_vcdevice.${ko}
$insmod talpa_pedevice.${ko}

function open_close()
{
    nr=$1
    es=""
    run=$nr_runs

    while [ $nr -gt 0 ]; do
        es="$es $openclose -l$nr_loops &"
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

open_close_test "Clean kernel"

if test "$interceptor_module" = "syscall" -o "$interceptor_module" = "vfshook"; then
    if test "$interceptor_module" = "syscall"; then
        $insmod talpa_syscallhook.${ko}
    fi
    if test "$interceptor_module" = "vfshook"; then
        $insmod talpa_syscallhook.${ko} hook_mask=mu
    fi

    open_close_test "Hooked kernel"
fi

$insmod talpa_${interceptor_module}.${ko}
echo "-close" >/proc/sys/talpa/interceptors/${interceptor_name}/ops 2>/dev/null

open_close_test "Interceptor loaded"

echo "enable" >/proc/sys/talpa/interceptors/${interceptor_name}/status 2>/dev/null
open_close_test "Interceptor enabled"

talpa_unload

exit 0
