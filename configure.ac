#
# configure.ac
#
# TALPA Filesystem Interceptor
#
# Copyright (C) 2004-2006 Sophos Plc, Oxford, England.
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

#
# Bolierplate.
#
AC_INIT(talpa, 0.9.40)
AC_CONFIG_AUX_DIR(config)
AC_COPYRIGHT(Copyright (c) 2004-2006 Sophos PLC)

AM_INIT_AUTOMAKE([1.9 tar-ustar])
AM_INIT_AUTOMAKE([dist-zip dist-bzip2 dist-shar])
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE

#
# Programs.
#
AC_PROG_CC
AC_CHECK_TOOL(MODULELINKER, ld, :)
AC_PROG_EGREP
AC_PATH_PROG(CUT, cut)
AC_PATH_PROG(SED, sed)
AC_PATH_PROG(UNAME, uname)
AC_PROG_LN_S
AC_PATH_PROG(RM, rm)

#
# Options.
#
AC_PREFIX_DEFAULT(/opt/talpa)

AC_ARG_ENABLE(talpa-build,
            [  --disable-talpa-build          configure building of talpa [[build]]],
            [talpabuild=$enableval],
            [talpabuild=yes])

AC_ARG_WITH(kernel,
            [  --with-kernel=DIR                    specify the kernel that should be built against],
            [ AC_SUBST(kerneldir,[$withval])
              AC_SUBST(sourcedir,[$withval]) ],
            [ kernver=`${UNAME} -r`
              AC_SUBST(kerneldir,[/lib/modules/${kernver}/build])
              AC_SUBST(sourcedir,[/lib/modules/${kernver}/source]) ])

AC_ARG_WITH(kernel-include,
            [  --with-kernel-include=DIR:DIR        specify the include path for kernel header files that should be built against],
            [ AC_SUBST(kernelhdrspath,[$withval]) ],
            [ if test -s ${sourcedir}; then
                AC_SUBST(kernelhdrspath,[$kerneldir/include:$sourcedir/include])
              else
                AC_SUBST(kernelhdrspath,[$kerneldir/include])
              fi ])

AC_ARG_ENABLE(debug,
              [  --enable-debug                 enable debugging code],
              [ if test "$enableval" = "yes"; then
                    AC_SUBST(debug,"-DDEBUG -g")
                fi])

AC_ARG_ENABLE(assertions,
              [  --enable-assertions            turn on assertions],
              [ if test "$enableval" = "yes"; then
                    AC_SUBST(assert,"-DASSERT")
                fi])

AC_ARG_WITH(system-map,
              [  --with-system-map                    location of the System.map file [[autodetected]]],
              [ system_map=$withval
                auto_system_map=no ],
              [ auto_system_map=yes ])

AC_ARG_ENABLE(hidden-syscall-table,
                [  --enable-hidden-syscall-table  enable hunting for a hidden syscall table [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(hidden,"-DTALPA_HIDDEN_SYSCALLS")
                    fi
                    auto_hidden=no
                ],
                [   auto_hidden=yes ])

AC_ARG_ENABLE(new-parent,
                [  --enable-new-parent            enable support for 2.6 style task_struct on some patched 2.4 kernels [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(newparent,"-DTALPA_HAS_NEW_PARENT")
                    fi
                    auto_parent=no
                ],
                [   auto_parent=yes])

AC_ARG_ENABLE(dpath,
                [  --enable-dpath                 For example Fedora FC5 exports __d_path which is unusual for 2.6 kernels [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(dpath,"-DTALPA_HAS_DPATH")
                    fi
                    auto_dpath=no
                ],
                [   auto_dpath=yes])

AC_ARG_ENABLE(path-lookup,
                [  --enable-path-lookup           some kernels older than 2.4.25 have backported a change which exports path_lookup [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(pathlookup,"-DTALPA_HAS_PATH_LOOKUP")
                    fi
                    auto_pathlookup=no
                ],
                [   auto_pathlookup=yes])

AC_ARG_ENABLE(task-new-tty,
                [  --enable-task-new-tty          SuSE Enterprise Server 9 2.6.5 kernel has a task_struct from later kernels [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(tasknewtty,"-DTALPA_HAS_TASK_NEW_TTY")
                    fi
                    auto_tasknewtty=no
                ],
                [   auto_tasknewtty=yes])

AC_ARG_ENABLE(backported-rcu,
                [  --enable-backported-rcu        Fedora FC4 2.6.11 has rcpudate.h backported from vanilla 2.6.12 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(rcubackport,"-DTALPA_HAS_BACKPORTED_RCU")
                    fi
                    auto_rcubackport=no
                ],
                [   auto_rcubackport=yes])

AC_ARG_ENABLE(backported-mutexes,
                [  --enable-backported-mutexes    Fedora FC5 2.6.15 has mutexes backported from vanilla 2.6.16 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(mutexbackport,"-DTALPA_HAS_MUTEXES")
                    fi
                    auto_mutexbackport=no
                ],
                [   auto_mutexbackport=yes])

AC_ARG_ENABLE(inode_mutexes,
                [  --enable-inode_mutexes         Later RedHat Enterprise 4 kernels have backported mutexes without the inode changes [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(inodemutex,"-DTALPA_INODE_USES_MUTEXES")
                    fi
                    auto_inodemutex=no
                ],
                [   auto_inodemutex=yes])

AC_ARG_ENABLE(inode_iprivate,
                [  --enable-inode_iprivate        RedHat Enterprise 5 kernels have this field backported [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(inodeiprivate,"-DTALPA_INODE_I_PRIVATE")
                    fi
                    auto_inodeiprivate=no
                ],
                [   auto_inodeiprivate=yes])

AC_ARG_ENABLE(backported-signal,
                [  --enable-backported-signal     Fedora FC4 2.6.11 has the task_struct->signal backported from vanilla 2.6.12 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(signalbackport,"-DTALPA_HAS_BACKPORTED_SIGNAL")
                    fi
                    auto_signalbackport=no
                ],
                [   auto_signalbackport=yes])

AC_ARG_ENABLE(backported-jiffies,
                [  --enable-backported-jiffies    Updated SLES9 kernel can have features backported from newer versions [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(jiffiesbackport,"-DTALPA_HAS_BACKPORTED_JIFFIES")
                    fi
                    auto_jiffiesbackport=no
                ],
                [   auto_jiffiesbackport=yes])

AC_ARG_ENABLE(backported-filldir,
                [  --enable-backported-filldir    More recent filldir_t callbacks pass u64 for inode number [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(filldirbackport,"-DTALPA_HAS_BACKPORTED_FILLDIR")
                    fi
                    auto_filldirbackport=no
                ],
                [   auto_filldirbackport=yes])

AC_ARG_ENABLE(no-tasklist-lock,
                [  --enable-no-tasklist-lock      Starting with vanilla 2.6.18 tasklist_lock is no longer exported [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(notasklistlock,"-DTALPA_NO_TASKLIST_LOCK")
                    fi
                    auto_notasklistlock=no
                ],
                [   auto_notasklistlock=yes])

AC_ARG_ENABLE(vfsmount-lock,
                [  --enable-vfsmount-lock         Use vfsmount_lock when creating path names [[autodetected]]],
                [ auto_vfsmntlock=$enableval ],
                [ auto_vfsmntlock=yes])

AC_ARG_ENABLE(lsm,
                [  --enable-lsm                   try to build LSM dependent modules [[autodetected]]],
                [   auto_lsm=no
                    AC_SUBST(lsm,$enableval) ],
                [   auto_lsm=yes])

AC_ARG_ENABLE(lsm-keys,
                [  --enable-lsm-keys              LSM implementation has keys support [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(lsmkeys,"-DTALPA_HAS_LSM_KEYS")
                    fi
                    auto_lsmkeys=no
                ],
                [   auto_lsmkeys=yes])

AC_ARG_ENABLE(lsm-2614,
                [  --enable-lsm-2614              for example Turbolinux Server 10 x64 2.6.13 kernels have LSM backported from 2.6.14 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(lsm2614,"-DTALPA_HAS_2614_LSM")
                    fi
                    auto_lsm2614=no
                ],
                [   auto_lsm2614=yes])

AC_ARG_ENABLE(lsm-2610,
                [  --enable-lsm-2610              for example RHAS 4.0 2.6.9 kernel has LSM backported from 2.6.10 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(lsm2610,"-DTALPA_HAS_2610_LSM")
                    fi
                    auto_lsm2610=no
                ],
                [   auto_lsm2610=yes])

AC_ARG_ENABLE(lsm-266,
                [  --enable-lsm-266               for example Fedora Core 2 2.6.5 kernel has LSM backported from 2.6.6 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(lsm266,"-DTALPA_HAS_266_LSM")
                    fi
                    auto_lsm266=no
                ],
                [   auto_lsm266=yes])

AC_ARG_ENABLE(lsm-265,
                [  --enable-lsm-265               for example SuSE-s 9.1 2.6.4 kernel has LSM backported from 2.6.5 [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(lsm265,"-DTALPA_HAS_265_LSM")
                    fi
                    auto_lsm265=no
                ],
                [   auto_lsm265=yes])

AC_ARG_WITH(test-interceptor,
            [  --with-test-interceptor=INTERCEPTOR  specify interceptor to use for testing (lsm,syscall,vfshook) [[default]]],
            [testinterceptor=$withval],
            [testinterceptor=default])

AC_ARG_ENABLE(hrtimers,
              [  --enable-hrtimers              are hrtimers exported [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(hrtimers,"-DTALPA_HAS_HRTIMERS")
                    fi
                    auto_hrtimers=no
                ],
                [   auto_hrtimers=yes])

AC_ARG_ENABLE(x-workaround,
              [  --disable-x-workaround         disable X server workaround where open(2) fails with -EINTR because itimers are not honoured [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(xhack,"-DTALPA_HAS_XHACK")
                    fi
                    auto_xhack=no
                ],
                [   auto_xhack=yes
                    AC_SUBST(xhack,"-DTALPA_HAS_XHACK")

                ])

AC_ARG_WITH(stacker,
              [  --with-stacker                       should additional and unsupported LSM stacking module be built [[yes]]],
              [ buildstacker=$withval
                if test "$withval" = "yes"; then
                    AM_CONDITIONAL(BUILDSTACKER, test 1 -eq 1)
                else
                    AM_CONDITIONAL(BUILDSTACKER, test 0 -eq 1)
                fi ],
              [ buildstacker=no
                AM_CONDITIONAL(BUILDSTACKER, test 0 -eq 1)
              ])

AC_ARG_ENABLE(syscallhook,
              [  --enable-syscallhook           should talpa_syscallhook module be built depends on whether system call table is read-only or not [[autodetected]]],
              [ auto_syscallhook=no
                AC_SUBST(syscallhook, $enableval) ],
              [ auto_syscallhook=yes])

AC_ARG_ENABLE(same-file,
              [  --enable-same-file             should file being intercepted be directly used for stream interface operations or a new copy opened [[disabled]]],
              [ if test $enableval = "yes"; then
                    AC_SUBST(samefile, "-DTALPA_SAME_FILE")
                else
                    AC_SUBST(samefile, "")
                fi ],
              [ AC_SUBST(samefile, "") ])

AC_ARG_ENABLE(securityfs,
                [  --enable-securityfs            use securityfs for the configuration system [[autodetected]]],
                [   auto_securityfs=no
                    if test "$enableval" = "yes"; then
                        AC_SUBST(securityfs, "-DTALPA_HAS_SECURITYFS")
                        AC_SUBST(buildsecurityfs, "yes")
                        AM_CONDITIONAL(BUILDSECURITYFS, test 1 -eq 1)
                    else
                        AC_SUBST(buildsecurityfs, "no")
                        AM_CONDITIONAL(BUILDSECURITYFS, test 0 -eq 1)
                    fi ],
                [   auto_securityfs=yes])

AC_ARG_WITH(legacy-configurator,
                [  --without-legacy-configurator        keep procfs configuration system when securityfs is in use [[enabled]]],
                [ wantdualfs="$withval" ],
                [ wantdualfs="yes"])

AC_ARG_ENABLE(test-warnings-errors,
                [  --disable-test-warnings-errors disable warnings as errors when compiling configure test programs [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        auto_warnings=force
                    else
                        auto_warnings=
                    fi ],
                [   auto_warnings=yes])

CFLAGS=

#
# Should we build?
#
if test "$talpabuild" = "yes"; then

#
# Setup our search macros.
#
# TALPA_LOCATE_DIR(name, path, [action-if-found], [action-if-not-found])
#--------------------------------------------------------------------------
AC_DEFUN([TALPA_LOCATE_DIR],
[
file_found="false"
for searchdir in `echo $2 | ${SED} 's/:/ /g'`
  do
    if test -d $searchdir/$1; then
        file_found="true"
        TALPA_DIR_LOCATION=$searchdir
    fi
  done
if test "$file_found" = "false"; then
    TALPA_DIR_LOCATION=
    checkString=`sed -e 's/"/\\"/g' <<++++
$4
++++`
    if test "$checkString" != ""; then
        eval "$checkString"
    fi
 else
    checkString=`sed -e 's/"/\\"/g' <<++++
$3
++++`
    if test "checkString" != ""; then
        eval "$checkString"
    fi
fi])

# TALPA_LOCATE_FILE(name, path, [action-if-found], [action-if-not-found])
#--------------------------------------------------------------------------
AC_DEFUN([TALPA_LOCATE_FILE],
[
file_found="false"
for searchdir in `echo $2 | ${SED} 's/:/ /g'`
  do
    if test -f $searchdir/$1; then
        file_found="true"
        TALPA_FILE_LOCATION=$searchdir
    fi
  done
if test "$file_found" = "false"; then
    TALPA_FILE_LOCATION=
    checkString=`sed -e 's/"/\\"/g' <<++++
$4
++++`
    if test "$checkString" != ""; then
        eval "$checkString"
    fi
 else
    checkString=`sed -e 's/"/\\"/g' <<++++
$3
++++`
    if test "checkString" != ""; then
        eval "$checkString"
    fi
fi])

# TALPA_LOCATE_HEADER(name, path, [action-if-found], [action-if-not-found], [quiet])
#--------------------------------------------------------------------------
AC_DEFUN([TALPA_LOCATE_HEADER],
[
if test "$5" = ""; then
    AC_MSG_CHECKING([for $1])
fi
hdr_found="false"
for hdrdir in `echo $2 | ${SED} 's/:/ /g'`
  do
    if test -f $hdrdir/$1; then
        hdr_found="true"
        TALPA_HEADER_LOCATION=$hdrdir
    fi
  done
if test "$hdr_found" = "false"; then
    checkString=`sed -e 's/"/\\"/g' <<++++
$4
++++`
    if test "$checkString" != ""; then
        eval "$checkString"
    else
        TALPA_HEADER_LOCATION=
        checkString=`sed -e 's/"/\\"/g' <<++++
$5
++++`
        if test "$checkString" = ""; then
            AC_MSG_ERROR(cannot proceed without the required header file)
        else
            AC_MSG_ERROR(Unable to find $1. Cannot proceed.)
        fi
    fi
 else
    checkString=`sed -e 's/"/\\"/g' <<++++
$3
++++`
    if test "$checkString" != ""; then
        eval "$checkString"
    else
        checkString=`sed -e 's/"/\\"/g' <<++++
$5
++++`
        if test "$checkString" = ""; then
            AC_MSG_RESULT(yes)
        fi
    fi
fi])

# TALPA_INCLUDE_PATH(path)
#--------------------------------------------------------------------------
AC_DEFUN([TALPA_INCLUDE_PATH],
[-I`echo $1 | ${SED} 's/:/ -I/g'`])

#
# Headers.
#
TALPA_LOCATE_HEADER(linux/version.h, $kernelhdrspath)
TALPA_LOCATE_HEADER(linux/autoconf.h, $kernelhdrspath)

#
# Autodetect platform we are running on.
#
AC_MSG_CHECKING([for operating system])
platform=`${UNAME} -s`
if test "$platform" = "GNU/Linux" -o "$platform" = "Linux"; then
    if test -L ${srcdir}/src/ifaces/platform -o -d ${srcdir}/src/ifaces/platform; then
        ${RM} -rf ${srcdir}/src/ifaces/platform
    fi
    (cd ${srcdir}/src/ifaces && ${LN_S} platforms/linux platform)
    if test $? -ne 0; then
        AC_MSG_ERROR([setup failed])
    fi
    AC_MSG_RESULT([${platform}])
else
    AC_MSG_ERROR([failed])
fi

#
# Autodetect kernel version.
#

if test ! -d tests/configure; then
    mkdir -p tests/configure
fi

# Test if and how we can compile test programs
AC_MSG_CHECKING([for compilation environment])
if test "$auto_warnings" = "yes"; then
    if ! ${CC} -Werror -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) ${srcdir}/tests/configure/kernelheaders.c -o /dev/null 1>/dev/null 2>&1; then
        if ! ${CC} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) ${srcdir}/tests/configure/kernelheaders.c -o /dev/null 1>/dev/null 2>&1; then
            AC_MSG_ERROR([unable to compile test programs])
        else
            AC_MSG_RESULT([warnings as errors turned off])
            AC_SUBST(werror,"")
        fi
    else
        AC_MSG_RESULT([ok])
        AC_SUBST(werror,"-Werror")
    fi
elif test "$auto_warnings" = "force"; then
    AC_MSG_RESULT([forced ok])
    AC_SUBST(werror,"-Werror")
else
    AC_MSG_RESULT([forced no warnings as errors])
    AC_SUBST(werror,"")
fi

AC_MSG_CHECKING([for kernel architecture])
${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) ${srcdir}/tests/configure/kernarch.c -o tests/configure/kernarch
kern_arch=`tests/configure/kernarch`
AC_MSG_RESULT([${kern_arch}])
${RM} -f tests/configure/kernarch
if test "$kern_arch" = "unsupported"; then
    AC_MSG_ERROR([kernel architecture not supported])
else
    # Set here but will be cleared below if recent 2.6 kernel is detected
    AC_SUBST(execve,"-DTALPA_EXECVE_SUPPORT")
fi

AC_MSG_CHECKING([for kernel version code])
${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) ${srcdir}/tests/configure/kernversion.c -o tests/configure/kernversion
kern_version_code=`tests/configure/kernversion`
AC_MSG_RESULT([${kern_version_code}])
${RM} -f tests/configure/kernversion
AC_MSG_CHECKING([for kernel version string])
TALPA_LOCATE_HEADER(linux/utsrelease.h, $kernelhdrspath, cckernrelease="-DSEPARATE_UTS_RELEASE", /bin/true, [quiet])
${CC} ${werror} -pipe -D__KERNEL__ $cckernrelease TALPA_INCLUDE_PATH($kernelhdrspath) ${srcdir}/tests/configure/kernrelease.c -o tests/configure/kernrelease
kern_uts_release=`tests/configure/kernrelease`
AC_MSG_RESULT([${kern_uts_release}])
${RM} -f tests/configure/kernrelease

AM_CONDITIONAL(KBUILD26, test $((kern_version_code)) -ge 132608)
# Set these to true for time being
AM_CONDITIONAL(TESTXWORKAROUND, test 1 -eq 1)

# Select interceptor to use for testing
case $testinterceptor in
    default)
        AC_SUBST(interceptor_module,vfshook)
        AC_SUBST(interceptor_name,VFSHookInterceptor)
        ;;
    best)
        if test $((kern_version_code)) -ge 132608; then
            AC_SUBST(interceptor_module,lsm)
            AC_SUBST(interceptor_name,LSMInterceptor)
        else
            AC_SUBST(interceptor_module,vfshook)
            AC_SUBST(interceptor_name,VFSHookInterceptor)
        fi
        ;;
    syscall)
        AC_SUBST(interceptor_module,syscall)
        AC_SUBST(interceptor_name,SyscallInterceptor)
        ;;
    lsm)
        AC_SUBST(interceptor_module,lsm)
        AC_SUBST(interceptor_name,LSMInterceptor)
        ;;
    vfshook)
        AC_SUBST(interceptor_module,vfshook)
        AC_SUBST(interceptor_name,VFSHookInterceptor)
        ;;
    *)
        AC_MSG_ERROR(Unknown interceptor)
        ;;
esac

# Try to find the System.map file
AC_MSG_CHECKING([for System.map])
if test "$auto_system_map" = "yes"; then
    system_map="/boot/System.map-${kern_uts_release}"
fi
if test ! -f "$system_map"; then
    AC_MSG_ERROR([$system_map not found])
    system_map=""
else
    AC_MSG_RESULT([$system_map])
fi

# Check for do_truncate address
AC_MSG_CHECKING([for do_truncate address])
tmp=`${EGREP} " do_truncate" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
if test "$tmp" != ""; then
    AC_MSG_RESULT([0x$tmp])
    AC_SUBST(dotruncateaddr, "-DTALPA_DOTRUNCATE_ADDR=0x$tmp")
else
    AC_MSG_ERROR([not found])
fi

# Check for do_truncate type
TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath)
TALPA_LOCATE_DIR(asm/mach-default, $kernelhdrspath)
AC_MSG_CHECKING([for do_truncate type])
let hitcnt=0
${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/dotruncate1.c -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=($hitcnt)+1
    AC_SUBST(dotruncatetype, "-DTALPA_DOTRUNCATE_1")
    AC_MSG_RESULT([type 1])
fi
${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/dotruncate2.c -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=($hitcnt)+1
    AC_SUBST(dotruncatetype, "-DTALPA_DOTRUNCATE_2")
    AC_MSG_RESULT([type 2])
fi
${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/dotruncate3.c -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=($hitcnt)+1
    AC_SUBST(dotruncatetype, "-DTALPA_DOTRUNCATE_3")
    AC_MSG_RESULT([type 3])
fi
${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/dotruncaterh4.c -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=($hitcnt)+1
    AC_SUBST(dotruncatetype, "-DTALPA_DOTRUNCATE_RH4")
    AC_MSG_RESULT([type rh4])
fi
${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/dotruncatesuse103.c -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=($hitcnt)+1
    AC_SUBST(dotruncatetype, "-DTALPA_DOTRUNCATE_SUSE103")
    AC_MSG_RESULT([type suse103])
fi
if test $hitcnt -eq 0 ; then
    AC_MSG_ERROR([unknown])
fi
if test $hitcnt -gt 1 ; then
    AC_MSG_ERROR([ambigous])
fi

# Check for vfs_unlink type
TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath)
TALPA_LOCATE_DIR(asm/mach-default, $kernelhdrspath)
AC_MSG_CHECKING([for vfs_unlink type])
let hitcnt=0
${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/unlink.c -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=($hitcnt)+1
    AC_SUBST(vfsunlink, "-DTALPA_VFSUNLINK_STANDARD")
    AC_MSG_RESULT([standard])
fi
${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/unlinksuse103.c -o /dev/null 1>/dev/null 2>&1
if test $? -eq 0; then
    let hitcnt=($hitcnt)+1
    AC_SUBST(vfsunlink, "-DTALPA_VFSUNLINK_SUSE103")
    AC_MSG_RESULT([suse103])
fi
if test $hitcnt -eq 0 ; then
    AC_MSG_ERROR([unknown])
fi
if test $hitcnt -gt 1 ; then
    AC_MSG_ERROR([ambigous])
fi

# Check for snprintf only for kernels older than 2.4.10
if test $((kern_version_code)) -lt 132106; then
    TALPA_LOCATE_HEADER(linux/kernel.h, $kernelhdrspath)
    AC_MSG_CHECKING([for snprintf])
    ${EGREP} snprintf $TALPA_HEADER_LOCATION/linux/kernel.h >/dev/null 2>&1
    if test $? -eq 0; then
        AC_MSG_RESULT([present])
        AC_SUBST(snprintf,"-DTALPA_HAS_SNPRINTF")
    else
        AC_MSG_RESULT([not present])
    fi
fi

# Check for tasklist_lock export
if test "$auto_notasklistlock" = "yes"; then
    AC_MSG_CHECKING([for tasklist_lock export])
    if test $((kern_version_code)) -ge 132608; then
        if test $((kern_version_code)) -ge 132626; then
            AC_SUBST(notasklistlock,"-DTALPA_NO_TASKLIST_LOCK")
            AC_MSG_RESULT([not available])
        elif test -f $kerneldir/kernel/fork.c; then
            ${EGREP} EXPORT_SYMBOL\\\(tasklist_lock\\\)\; $kerneldir/kernel/fork.c >/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([available])
            else
                AC_SUBST(notasklistlock,"-DTALPA_NO_TASKLIST_LOCK")
                AC_MSG_RESULT([not available])
            fi
        elif test -f $sourcedir/kernel/fork.c; then
            ${EGREP} EXPORT_SYMBOL\\\(tasklist_lock\\\)\; $sourcedir/kernel/fork.c >/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([available])
            else
                AC_SUBST(notasklistlock,"-DTALPA_NO_TASKLIST_LOCK")
                AC_MSG_RESULT([not available])
            fi
        else
            AC_MSG_RESULT([unknown, assuming available])
        fi
    else
        AC_MSG_RESULT([available (2.4)])
    fi
fi

# Find tasklist_lock address if not exported
if test "$notasklistlock" != ""; then
    AC_MSG_CHECKING([for tasklist_lock address])
    tasklist_lock_addr=`${EGREP} " tasklist_lock" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
    if test "$tasklist_lock_addr" != ""; then
        AC_MSG_RESULT([0x$tasklist_lock_addr])
        AC_SUBST(notasklistlock, "$notasklistlock -DTALPA_TASKLIST_LOCK_ADDR=0x$tasklist_lock_addr")
    else
        AC_MSG_ERROR([not found])
    fi
fi

function find_syscall_table
{
    sys_call_table=`${EGREP} " sys_call_table" "$1" 2>/dev/null | ${CUT} -d ' ' -f 1`
    if test "$sys_call_table" = ""; then
        return 1
    fi

    march=`${UNAME} -m`
    if test "$march" = "x86_64"; then
        sys_call_table32=`${EGREP} " ia32_sys_call_table" "$1" 2>/dev/null | ${CUT} -d ' ' -f 1`
        if test "$sys_call_table32" = ""; then
            return 1
        fi

        # If passed through environment do nothing since makefile will handle that
        if test "$TALPA_SYSCALL_TABLE" = "" -a "$TALPA_SYSCALL32_TABLE" = ""; then
            FIND_SYSCALL_TABLE_RESULT="-DTALPA_SYSCALL_TABLE=0x${sys_call_table} -DTALPA_SYSCALL32_TABLE=0x${sys_call_table32}"
            return 0
        fi

        return 1
    fi

    if test "$TALPA_SYSCALL_TABLE" = ""; then
        FIND_SYSCALL_TABLE_RESULT="-DTALPA_SYSCALL_TABLE=0x${sys_call_table}"
        return 0
    fi

    return 1
}

AC_MSG_CHECKING([for appropriate build system])
if test $((kern_version_code)) -ge 132608; then
    AC_MSG_RESULT([2.6 build system detected])
    AC_SUBST(ko,ko)
    AC_SUBST(talpaversion, "-DTALPA_VERSION=\\\\\"${PACKAGE_VERSION}\\\\\"")
    # Test whether kbuild uses M= or SUBDIRS=, 2.6.8 was the first kernel to use M=
    AM_CONDITIONAL(KBUILDUSEM, test $((kern_version_code)) -ge 132616)

    AC_SUBST(hidden,"-DTALPA_HIDDEN_SYSCALLS")
    if find_syscall_table "$system_map"; then
        AC_SUBST(hidden,"${hidden} ${FIND_SYSCALL_TABLE_RESULT}")
    fi

    # Check for exported __d_path
    if test "$auto_dpath" = "yes"; then
        AC_MSG_CHECKING([for exported __d_path])
        if test -f "$kerneldir/fs/dcache.c"; then
            ${EGREP} EXPORT_SYMBOL\\\(__d_path\\\)\; $kerneldir/fs/dcache.c >/dev/null 2>&1
            if test $? -ne 0; then
                AC_MSG_RESULT([hidden])
            else
                AC_SUBST(dpath,"-DTALPA_HAS_DPATH")
                AC_MSG_RESULT([exported])
            fi
        elif test -f "$sourcedir/fs/dcache.c"; then
            ${EGREP} EXPORT_SYMBOL\\\(__d_path\\\)\; $sourcedir/fs/dcache.c >/dev/null 2>&1
            if test $? -ne 0; then
                AC_MSG_RESULT([hidden])
            else
                AC_SUBST(dpath,"-DTALPA_HAS_DPATH")
                AC_MSG_RESULT([exported])
            fi
        else
            AC_MSG_RESULT([undetectable])
        fi
    fi

    # Id __d_path is exported determine it's prototype
    if test "$dpath" = "-DTALPA_HAS_DPATH"; then
        TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath)
        TALPA_LOCATE_DIR(asm/mach-default, $kernelhdrspath)
        AC_MSG_CHECKING([for __d_path type])
        let hitcnt=0
        ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/dpath.c -o /dev/null 1>/dev/null 2>&1
        if test $? -eq 0; then
            let hitcnt=($hitcnt)+1
            AC_SUBST(dpath, "$dpath -DTALPA_DPATH_STANDARD")
            AC_MSG_RESULT([standard])
        fi
        ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/dpathsuse103.c -o /dev/null 1>/dev/null 2>&1
        if test $? -eq 0; then
            let hitcnt=($hitcnt)+1
            AC_SUBST(dpath, "$dpath -DTALPA_DPATH_SUSE103")
            AC_MSG_RESULT([suse103])
        fi
        if test $hitcnt -eq 0 ; then
            AC_MSG_ERROR([unknown])
        fi
        if test $hitcnt -gt 1 ; then
            AC_MSG_ERROR([ambigous])
        fi
    fi

    # Find vfsmnt_lock address
    if test "$auto_vfsmntlock" = "yes" -a "$dpath" = ""; then
        AC_MSG_CHECKING([for vfsmount_lock address])
        vfsmnt_lock_addr=`${EGREP} " vfsmount_lock" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
        if test "$vfsmnt_lock_addr" != ""; then
            AC_MSG_RESULT([0x$vfsmnt_lock_addr])
            AC_SUBST(vfsmntlock, "-DTALPA_USE_VFSMOUNT_LOCK -DTALPA_VFSMOUNT_LOCK_ADDR=0x$vfsmnt_lock_addr")
        else
            AC_MSG_ERROR([not found])
        fi
    fi

    # some 2.6 kernels do not export do_execve (vanilla >=2.6.10 and some vendor ones)
    AC_MSG_CHECKING([for syscallhook module execve support])
    if test -f $kerneldir/fs/exec.c; then
        ${EGREP} EXPORT_SYMBOL\\\(do_execve\\\)\; $kerneldir/fs/exec.c >/dev/null 2>&1
        if test $? -ne 0; then
            AC_SUBST(execve,"")
        fi
    elif test -f $sourcedir/fs/exec.c; then
        ${EGREP} EXPORT_SYMBOL\\\(do_execve\\\)\; $sourcedir/fs/exec.c >/dev/null 2>&1
        if test $? -ne 0; then
            AC_SUBST(execve,"")
        fi
    else
        AC_SUBST(execve,"")
    fi

    # Attempt to fetch do_execve address if not exported
    if test "$execve" == ""; then
        do_execve_addr=`${EGREP} " do_execve" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
        if test "$do_execve_addr" != ""; then
            AC_SUBST(execve, "-DTALPA_EXECVE_SUPPORT -DTALPA_HIDDEN_EXECVE -DTALPA_HIDDEN_EXECVE_ADDRESS=0x$do_execve_addr")
        fi
    fi

    # Finally output result of do_execve search
    if test "$execve" != ""; then
        if test "$do_execve_addr" == ""; then
            AC_MSG_RESULT([available])
        else
            AC_MSG_RESULT([available (0x$do_execve_addr)])
        fi
    else
        AC_MSG_RESULT([not available])
    fi

    # Autodetect if we are running on 2.6.5 with backported sched.h
    if test $((kern_version_code)) -le 132613; then
        if test "$auto_tasknewtty" = "yes"; then
            TALPA_LOCATE_HEADER(linux/sched.h, $kernelhdrspath)
            TALPA_LOCATE_DIR(asm/mach-default, $kernelhdrspath)
            AC_MSG_CHECKING([for backported sched.h])
            ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/tasktty.c -o /dev/null 1>/dev/null 2>&1
            if test $? -ne 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(tasknewtty,"-DTALPA_HAS_TASK_NEW_TTY")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Autodetect if rcupdate.h was backported
    if test $((kern_version_code)) -lt 132620; then
        if test "$auto_rcubackport" = "yes"; then
            AC_MSG_CHECKING([for backported rcupdate.h])
            ${EGREP} "deprecated.*synchronize_kernel" $TALPA_HEADER_LOCATION/linux/rcupdate.h >/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(rcubackport,"-DTALPA_HAS_BACKPORTED_RCU")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Autodetect if mutexes were backported
    if test $((kern_version_code)) -lt 132624; then
        if test "$auto_mutexbackport" = "yes"; then
            TALPA_LOCATE_HEADER(linux/mutex.h, $kernelhdrspath, /bin/true, /bin/false , [quiet])
            AC_MSG_CHECKING([for backported mutexes])
            if grep -q "struct mutex" "$TALPA_HEADER_LOCATION/linux/mutex.h" 2>/dev/null; then
                AC_MSG_RESULT([detected])
                AC_SUBST(mutexbackport,"-DTALPA_HAS_MUTEXES")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    else
        # Kernels starting with 2.6.16 have them
        AC_SUBST(mutexbackport,"-DTALPA_HAS_MUTEXES")
    fi

    # Autodetect if struct inode uses mutexes
    if test $((kern_version_code)) -lt 132624 -a "$mutexbackport" != ""; then
        if test "$auto_inodemutex" = "yes"; then
            TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath, /bin/true, /bin/false , [quiet])
            AC_MSG_CHECKING([for i_mutex inode struct member])
            ${EGREP} i_mutex\; $TALPA_HEADER_LOCATION/linux/fs.h >/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(inodemutex,"-DTALPA_INODE_USES_MUTEXES")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    else
        if test "$mutexbackport" != ""; then
            # Kernels starting with 2.6.16 use them
            AC_SUBST(inodemutex,"-DTALPA_INODE_USES_MUTEXES")
        fi
    fi

    # Autodetect if struct inode has i_private field
    if test $((kern_version_code)) -lt 132627; then
        if test "$auto_inodeiprivate" = "yes"; then
            TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath, /bin/true, /bin/false , [quiet])
            AC_MSG_CHECKING([for i_private inode struct member])
            ${EGREP} i_private\; $TALPA_HEADER_LOCATION/linux/fs.h >/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(inodeiprivate,"-DTALPA_INODE_I_PRIVATE")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Autodetect if task_struct->signal was backported
    if test $((kern_version_code)) -lt 132620; then
        if test "$auto_signalbackport" = "yes"; then
            TALPA_LOCATE_HEADER(linux/sched.h, $kernelhdrspath)
            TALPA_LOCATE_DIR(asm/mach-default, $kernelhdrspath)
            AC_MSG_CHECKING([for backported task_struct->signal])
            ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/tasksignal.c -o /dev/null 1>/dev/null 2>&1
            if test $? -ne 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(signalbackport,"-DTALPA_HAS_BACKPORTED_SIGNAL")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Autodetect if msecs_to_jiffies was backported
    if test $((kern_version_code)) -lt 132615; then
        if test "$auto_jiffiesbackport" = "yes"; then
            TALPA_LOCATE_HEADER(linux/time.h, $kernelhdrspath)
            TALPA_LOCATE_HEADER(linux/jiffies.h, $kernelhdrspath)
            TALPA_LOCATE_DIR(asm/mach-default, $kernelhdrspath)
            AC_MSG_CHECKING([for backported msecs_to_jiffies])
            ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default ${srcdir}/tests/configure/msecstojiffies.c -o /dev/null 1>/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(jiffiesbackport,"-DTALPA_HAS_BACKPORTED_JIFFIES")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Autodetect if filldir_t was backported
    if test $((kern_version_code)) -lt 132627; then
        if test "$auto_filldirbackport" = "yes"; then
            TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath, , ,[quiet])
            AC_MSG_CHECKING([for backported filldir])
            ${EGREP} "filldir_t.*u64" $TALPA_HEADER_LOCATION/linux/fs.h >/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(filldirbackport,"-DTALPA_HAS_BACKPORTED_FILLDIR")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Check whether to build syscallhook dependent modules
    AC_MSG_CHECKING([for system call table hooking support])
    if test "$auto_syscallhook" = "yes"; then
        TALPA_LOCATE_HEADER(linux/autoconf.h, $kernelhdrspath, , , [quiet])
        ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) ${srcdir}/tests/configure/rodata.c -o tests/configure/rodata
        tests/configure/rodata
        if test $? -eq 0; then
            AC_MSG_RESULT([yes])
            AC_SUBST(syscallhook, "yes")
        else
            # If passed through environment do nothing since makefile will handle that
            if test "$TALPA_RODATA_START" = "" -a "$TALPA_RODATA_END" = ""; then
                start_rodata=`${EGREP} " __start_rodata" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
                end_rodata=`${EGREP} " __end_rodata" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
                if test "$start_rodata" != "" -a "$end_rodata" != ""; then
                    AC_MSG_RESULT([yes])
                    AC_SUBST(syscallhook, "yes")
                    AC_SUBST(rodata, "-DTALPA_HAS_RODATA -DTALPA_RODATA_START=0x$start_rodata -DTALPA_RODATA_END=0x$end_rodata")
                else
                    AC_MSG_RESULT([no])
                    AC_SUBST(syscallhook, "no")
                fi
            else
                AC_MSG_RESULT([yes])
                AC_SUBST(syscallhook, "yes")
                AC_SUBST(rodata, "-DTALPA_HAS_RODATA")
            fi
        fi
        ${RM} -f tests/configure/rodata
        # Get change_page_attr_addr on x86_64
        if test "$kern_arch" = "x86_64" -a "$syscallhook" = "yes" -a "$rodata" != ""; then
            # Test for blacklisted kernels - known to crash if rodata is used
            AC_MSG_CHECKING([for blacklisted kernels])
            blacklisted=""
            # Stock SUSE 10.1 x86_64
            if test "$kern_uts_release" = "2.6.16.13-4-default" -o "$kern_uts_release" = "2.6.16.13-4-smp"; then
                blacklisted="1"
            fi
            # All of RHEL 5
            if echo "$kern_uts_release" | ${EGREP} -q "\.el5$"; then
                blacklisted="1"
            fi
            # Result
            if test "$blacklisted" != ""; then
                AC_MSG_ERROR([known bad])
            else
                AC_MSG_RESULT([all fine])
            fi
            AC_MSG_CHECKING([for change_page_attr_addr symbol])
            kfuncchpgattraddr=`${EGREP} " change_page_attr_addr" "$system_map" 2>/dev/null | ${CUT} -d ' ' -f 1`
            if test "$kfuncchpgattraddr" != ""; then
                AC_MSG_RESULT([ok])
                AC_SUBST(kfuncchpgattraddr, "-DTALPA_KFUNC_CHANGE_PAGE_ATTR_ADDR=0x$kfuncchpgattraddr")
            else
                AC_MSG_ERROR([failed to get])
            fi
        fi
    else
        if test "$syscallhook" = "yes"; then
            AC_MSG_RESULT([manual yes])
        else
            AC_MSG_RESULT([manual no])
        fi
    fi

    if test "$syscallhook" = "no" -a "$interceptor_module" != "lsm"; then
        AC_SUBST(interceptor_module,lsm)
        AC_SUBST(interceptor_name,LSMInterceptor)
    fi

    # Check whether to build LSM related modules
    AC_MSG_CHECKING([for LSM support])
    if test "$auto_lsm" = "yes"; then
        TALPA_LOCATE_HEADER(linux/autoconf.h, $kernelhdrspath, , , [quiet])
        ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) ${srcdir}/tests/configure/lsm.c -o tests/configure/lsm
        tests/configure/lsm
        if test $? -eq 0; then
            AC_MSG_RESULT([present])
            AC_SUBST(lsm, "yes")
            AM_CONDITIONAL(BUILDLSM, test 1 -eq 1)
            # Autodetect if we are compiling for a 2.6.0-test in which case we will disable LSM modules
            if test $((kern_version_code)) -eq 132608; then
                AC_MSG_CHECKING([for 2.6.0-test kernel])
                echo ${kern_uts_release} | ${EGREP} test >/dev/null 2>&1
                if test $? -eq 0; then
                    AC_MSG_RESULT([disabling LSM modules])
                    AC_SUBST(lsm, "no")
                    AM_CONDITIONAL(BUILDLSM, test 0 -eq 1)
                else
                    AC_MSG_RESULT([everything is fine])
                fi
            fi
        else
            AC_MSG_RESULT([not present])
            AC_SUBST(lsm, "no")
            AM_CONDITIONAL(BUILDLSM, test 0 -eq 1)
        fi
        ${RM} -f tests/configure/lsm
    else
        if test "$lsm" = "yes"; then
            AC_MSG_RESULT([forced])
            AC_SUBST(lsm, "yes")
            AM_CONDITIONAL(BUILDLSM, test 1 -eq 1)
        else
            AC_MSG_RESULT([disabled])
            AC_SUBST(lsm, "no")
            AM_CONDITIONAL(BUILDLSM, test 0 -eq 1)
        fi
    fi

    if test "$lsm" = "yes"; then
        # Autodetect LSM backports
        TALPA_LOCATE_HEADER(linux/security.h, $kernelhdrspath)
        TALPA_LOCATE_DIR(asm/mach-default, $kernelhdrspath)

        # Autodetect if LSM has key support
        if test "$auto_lsmkeys" = "yes"; then
            AC_MSG_CHECKING([for LSM key support])
            ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/lsmkeys.c -o /dev/null 1>/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(lsmkeys,"-DTALPA_HAS_LSM_KEYS")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi

        if test $((kern_version_code)) -le 132621; then
            # Autodetect if LSM from 2.6.14 is backported to the earlier version
            if test "$auto_lsm2614" = "yes"; then
                AC_MSG_CHECKING([for 2.6.14 LSM])
                ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/lsm2614.c -o /dev/null 1>/dev/null 2>&1
                if test $? -eq 0; then
                    AC_MSG_RESULT([detected])
                    AC_SUBST(lsm2614,"-DTALPA_HAS_2614_LSM")
                else
                    AC_MSG_RESULT([not detected])
                fi
            fi
        fi

        if test $((kern_version_code)) -le 132617; then
            # Autodetect if LSM from 2.6.10 is backported to 2.6.9
            if test "$auto_lsm2610" = "yes"; then
                AC_MSG_CHECKING([for 2.6.10 LSM])
                ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/lsm2610.c -o /dev/null 1>/dev/null 2>&1
                if test $? -eq 0; then
                    AC_MSG_RESULT([detected])
                    AC_SUBST(lsm2610,"-DTALPA_HAS_2610_LSM")
                else
                    AC_MSG_RESULT([not detected])
                fi
            fi
        fi

        if test $((kern_version_code)) -le 132613; then
            # Autodetect if LSM from 2.6.6 is backported to 2.6.5
            if test "$auto_lsm266" = "yes"; then
                AC_MSG_CHECKING([for 2.6.6 LSM])
                ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/lsm266.c -o /dev/null 1>/dev/null 2>&1
                if test $? -ne 0; then
                    AC_MSG_RESULT([detected])
                    AC_SUBST(lsm266,"-DTALPA_HAS_266_LSM")
                else
                    AC_MSG_RESULT([not detected])
                fi
            fi

            # Autodetect if LSM from 2.6.5 is backported to 2.6.4
            if test $((kern_version_code)) -le 132612 -a $((kern_version_code)) -ge 132611; then
                if test "$auto_lsm265" = "yes"; then
                    AC_MSG_CHECKING([for 2.6.5 LSM])
                    ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/lsm265.c -o /dev/null 1>/dev/null 2>&1
                    if test $? -ne 0; then
                        AC_MSG_RESULT([detected])
                        AC_SUBST(lsm265,"-DTALPA_HAS_265_LSM")
                    else
                        AC_MSG_RESULT([not detected])
                    fi
                fi
            fi

        fi
    else
        # Do not run test with LSM inteceptor if it will not be built
        if test "$interceptor_module" = "lsm"; then
            AC_SUBST(interceptor_module,vfshook)
            AC_SUBST(interceptor_name,VFSHookInterceptor)
        fi
    fi

    # Check for hrtimers presence
    if test "$auto_hrtimers" = "yes"; then
        # Vanilla 2.6.16 has hrtimers but no exports. However, backports can exist.
        # Vanilla 2.6.17 exports the needed symbols but again handle backports as well.
        AC_MSG_CHECKING([for exported hrtimers])
        ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/hrtimersversion17.c -o /dev/null 1>/dev/null 2>&1
        if test $? -eq 0; then
            AC_SUBST(hrtimers,"-DTALPA_HAS_HRTIMERS")
            ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/hrtimersversion21.c -o /dev/null 1>/dev/null 2>&1
            if test $? -eq 0; then
                AC_SUBST(hrtimers,"$hrtimers -DTALPA_HAS_HRTIMERS_V21")
            fi
            AC_MSG_RESULT([present])
        else
            AC_MSG_RESULT([missing])
        fi
    fi

    # Check whether xhack can be implemented
    if test "$auto_xhack" = "yes"; then
        if test "$hrtimers" = ""; then
            ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/hrtimersversion16.c -o /dev/null 1>/dev/null 2>&1
            if test $? -eq 0; then
                AC_SUBST(xhack,"")
            fi
        fi
    fi

    # Check whether to use securityfs
    AC_MSG_CHECKING([for securityfs support])
    if test "$auto_securityfs" = "yes"; then
        TALPA_LOCATE_HEADER(linux/security.h, $kernelhdrspath, , , [quiet])
        ${EGREP} securityfs_remove $TALPA_HEADER_LOCATION/linux/security.h >/dev/null 2>&1
        rc1=$?
        ${CC} ${werror} -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) ${srcdir}/tests/configure/security.c -o tests/configure/security
        tests/configure/security
        rc2=$?
        ${RM} -f tests/configure/security
        if test $rc1 -eq 0 -a $rc2 -eq 1; then
            AC_MSG_RESULT([present])
            AC_SUBST(buildsecurityfs, "yes")
            AC_SUBST(securityfs, "-DTALPA_HAS_SECURITYFS")
            AM_CONDITIONAL(BUILDSECURITYFS, test 1 -eq 1)
        else
            AC_MSG_RESULT([not present <$rc1/$rc2>])
            AC_SUBST(buildsecurityfs, "no")
            AM_CONDITIONAL(BUILDSECURITYFS, test 0 -eq 1)
        fi
    else
        if test "$buildsecurityfs" = "yes"; then
            AC_MSG_RESULT([forced])
        else
            AC_MSG_RESULT([disabled])
        fi
    fi

    # Check whether to use dualfs
    if test "$wantdualfs" = "yes"; then
        AC_MSG_CHECKING([for legacy configuration support])
        if test "$buildsecurityfs" != "yes"; then
            AC_SUBST(builddualfs, "no")
        else
            AC_SUBST(builddualfs, "yes")
        fi
        if test "$builddualfs" = "yes"; then
            AC_SUBST(dualfs, "-DTALPA_HAS_DUALFS")
            AM_CONDITIONAL(BUILDDUALFS, test 1 -eq 1)
            AC_MSG_RESULT([included])
        else
            AM_CONDITIONAL(BUILDDUALFS, test 0 -eq 1)
            AC_MSG_RESULT([no])
        fi
    fi

    ${SED} -e  "s/@talpaversion@/${talpaversion}/; \
                s/@debug@/${debug}/; \
                s/@assert@/${assert}/; \
                s/@dpath@/${dpath}/; \
                s/@newparent@/${newparent}/; \
                s/@dotruncatetype@/${dotruncatetype}/; \
                s/@dotruncateaddr@/${dotruncateaddr}/; \
                s/@vfsunlink@/${vfsunlink}/; \
                s/@tasknewtty@/${tasknewtty}/; \
                s/@rcubackport@/${rcubackport}/; \
                s/@mutexbackport@/${mutexbackport}/; \
                s/@inodemutex@/${inodemutex}/; \
                s/@inodeiprivate@/${inodeiprivate}/; \
                s/@signalbackport@/${signalbackport}/; \
                s/@jiffiesbackport@/${jiffiesbackport}/; \
                s/@filldirbackport@/${filldirbackport}/; \
                s/@buildlsm@/${lsm}/; \
                s/@lsm265@/${lsm265}/; \
                s/@lsm266@/${lsm266}/; \
                s/@lsm2610@/${lsm2610}/; \
                s/@lsm2614@/${lsm2614}/; \
                s/@lsmkeys@/${lsmkeys}/; \
                s/@hidden@/${hidden}/; \
                s/@execve@/${execve}/; \
                s/@xhack@/${xhack}/; \
                s/@hrtimers@/${hrtimers}/; \
                s/@buildstacker@/${buildstacker}/; \
                s/@syscallhook@/${syscallhook}/; \
                s/@rodata@/${rodata}/; \
                s/@kfuncchpgattraddr@/${kfuncchpgattraddr}/; \
                s/@notasklistlock@/${notasklistlock}/; \
                s/@vfsmntlock@/${vfsmntlock}/; \
                s/@samefile@/${samefile}/; \
                s/@buildsecurityfs@/${buildsecurityfs}/; s/@securityfs@/${securityfs}/; \
                s/@builddualfs@/${builddualfs}/; s/@dualfs@/${dualfs}/;" ${srcdir}/Makefile26.in >${srcdir}/Makefile

    ${SED} -e  "s/@talpaversion@/${talpaversion}/; \
                s/@debug@/${debug}/; \
                s/@assert@/${assert}/; \
                s/@dpath@/${dpath}/; \
                s/@newparent@/${newparent}/; \
                s/@dotruncatetype@/${dotruncatetype}/; \
                s/@dotruncateaddr@/${dotruncateaddr}/; \
                s/@vfsunlink@/${vfsunlink}/; \
                s/@tasknewtty@/${tasknewtty}/; \
                s/@rcubackport@/${rcubackport}/; \
                s/@mutexbackport@/${mutexbackport}/; \
                s/@inodemutex@/${inodemutex}/; \
                s/@inodeiprivate@/${inodeiprivate}/; \
                s/@signalbackport@/${signalbackport}/; \
                s/@jiffiesbackport@/${jiffiesbackport}/; \
                s/@filldirbackport@/${filldirbackport}/; \
                s/@buildlsm@/${lsm}/; \
                s/@lsm265@/${lsm265}/; \
                s/@lsm266@/${lsm266}/; \
                s/@lsm2610@/${lsm2610}/; \
                s/@lsm2614@/${lsm2614}/; \
                s/@lsmkeys@/${lsmkeys}/; \
                s/@hidden@/${hidden}/; \
                s/@execve@/${execve}/; \
                s/@xhack@/${xhack}/; \
                s/@hrtimers@/${hrtimers}/; \
                s/@buildstacker@/${buildstacker}/; \
                s/@syscallhook@/${syscallhook}/; \
                s/@rodata@/${rodata}/; \
                s/@kfuncchpgattraddr@/${kfuncchpgattraddr}/; \
                s/@notasklistlock@/${notasklistlock}/; \
                s/@vfsmntlock@/${vfsmntlock}/; \
                s/@samefile@/${samefile}/; \
                s/@buildsecurityfs@/${buildsecurityfs}/; s/@securityfs@/${securityfs}/; \
                s/@builddualfs@/${builddualfs}/; s/@dualfs@/${dualfs}/;" ${srcdir}/tests/modules/Makefile26.in >${srcdir}/tests/modules/Makefile
else
    AC_MSG_RESULT([2.4 build system detected])
    AC_SUBST(ko,o)
    AC_SUBST(talpaversion, "-DTALPA_VERSION=\\\"${PACKAGE_VERSION}\\\"")
    AM_CONDITIONAL(KBUILDUSEM, test 0 -eq 1)
    AM_CONDITIONAL(BUILDLSM, test 0 -eq 1)
    AM_CONDITIONAL(BUILDSECURITYFS, test 0 -eq 1)
    AM_CONDITIONAL(BUILDDUALFS, test 0 -eq 1)

    # Check for hidden syscall table
    if test "$auto_hidden" = "yes"; then
        AC_MSG_CHECKING([for syscall table])
        if test -f $kerneldir/kernel/ksyms.c; then
            ${EGREP} EXPORT_SYMBOL\\\(sys_call_table\\\)\; $kerneldir/kernel/ksyms.c >/dev/null 2>&1
            if test $? -ne 0; then
                AC_MSG_RESULT([hidden])
                AC_SUBST(hidden,"-DTALPA_HIDDEN_SYSCALLS")
                if find_syscall_table "$system_map"; then
                    AC_SUBST(hidden,"${hidden} ${FIND_SYSCALL_TABLE_RESULT}")
                fi
            else
                AC_MSG_RESULT([exported])
            fi
        else
            syscalls_unknown=yes
            AC_MSG_RESULT([skipped])
        fi
    fi

    # Check for exported path_lookup
    if test "$auto_pathlookup" = "yes"; then
        if test $((kern_version_code)) -lt 132121; then
            AC_MSG_CHECKING([for path_lookup])
            if test -f $kerneldir/kernel/ksyms.c; then
                ${EGREP} EXPORT_SYMBOL\\\(path_lookup\\\)\; $kerneldir/kernel/ksyms.c >/dev/null 2>&1
                if test $? -ne 0; then
                    AC_MSG_RESULT([hidden])
                else
                    AC_SUBST(pathlookup,"-DTALPA_HAS_PATH_LOOKUP")
                    AC_MSG_RESULT([exported])
                fi
            else
                AC_MSG_RESULT([undetectable])
            fi
        fi
    fi

    # Check for backported scheduler
    if test "$auto_parent" = "yes"; then
        TALPA_LOCATE_HEADER(linux/sched.h, $kernelhdrspath)
        AC_MSG_CHECKING([for backported scheduler])
        ${EGREP} parent\; $TALPA_HEADER_LOCATION/linux/sched.h >/dev/null 2>&1
        if test $? -eq 0; then
            AC_MSG_RESULT([found])
            AC_SUBST(newparent,"-DTALPA_HAS_NEW_PARENT")
        else
            AC_MSG_RESULT([original])
        fi
    fi

    # Check for backported prefetch.h
    if test $((kern_version_code)) -lt 132106; then
        AC_MSG_CHECKING([for backported prefetch.h])
        TALPA_LOCATE_FILE(linux/prefetch.h, $kernelhdrspath,
            [AC_MSG_RESULT([found])
            AC_SUBST(backportedprefetch,"-DTALPA_BACKPORTED_PREFETCH")],
            [AC_MSG_RESULT([not found])])
    fi
fi

AC_MSG_CHECKING([for X workaround])
if test "$xhack" != ""; then
    AC_MSG_RESULT([enabled])
else
    AC_MSG_RESULT([disabled])
    AM_CONDITIONAL(TESTXWORKAROUND, test 0 -eq 1)
fi

AC_SUBST(kernelincludes,TALPA_INCLUDE_PATH($kernelhdrspath))

#
# ...Should we build?
#
else
    # define these to please autoconf
    AM_CONDITIONAL(KBUILD26, test 1 -eq 1)
    AM_CONDITIONAL(KBUILDUSEM, test 0 -eq 1)
    AM_CONDITIONAL(BUILDLSM, test 1 -eq 1)
    AM_CONDITIONAL(BUILDSTACKER, test 1 -eq 1)
    AM_CONDITIONAL(BUILDSECURITYFS, test 1 -eq 1)
    AM_CONDITIONAL(BUILDDUALFS, test 1 -eq 1)
    ## Defined to be true so that tests are included in source tar file
    AM_CONDITIONAL(TESTXWORKAROUND, test 1 -eq 1)
fi


#
# Output.
#
AC_OUTPUT([makefile clients/Makefile tests/Makefile tests/modules/makefile tests/benchmark/Makefile])

if test "$syscalls_unknown" = "yes"; then
    echo -e "\nFailed to autodetect syscall table status - defaulting to exported.\nUse separate --with-kernel and --with-kernel-include, or set --enable-hidden-syscall-table.\n"
fi

#
# End of configure.ac
#
