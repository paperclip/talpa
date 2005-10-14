#
# configure.ac
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

#
# Bolierplate.
#
AC_INIT(talpa, 0.9.28)
AC_CONFIG_AUX_DIR(config)
AC_COPYRIGHT(Copyright (c) 2004-2005 Sophos PLC)

AM_INIT_AUTOMAKE([1.9 tar-ustar])
AM_INIT_AUTOMAKE([dist-zip dist-bzip2 dist-shar])
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE

AC_PROG_EGREP
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
            [  --with-kernel=DIR            specify the kernel that should be built against],
            [ AC_SUBST(kerneldir,[$withval])
              AC_SUBST(sourcedir,[$withval]) ],
            [ kernver=`${UNAME} -r`
              AC_SUBST(kerneldir,[/lib/modules/${kernver}/build])
              AC_SUBST(sourcedir,[/lib/modules/${kernver}/source]) ])

AC_ARG_WITH(kernel-include,
            [  --with-kernel-include=DIR:DIR    specify the include path for kernel header files that should be built against],
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

AC_ARG_ENABLE(inode-alloc-sem,
                [  --enable-inode-alloc-sem       kernels >= 2.4.22 and >= 2.6.6 have this field as some patched ones [[autodetected]]],
                [   if test "$enableval" = "yes"; then
                        AC_SUBST(inodeallocsem,"-DTALPA_HAS_INODE_ALLOC_SEM")
                    fi
                    auto_inode=no
                ],
                [   auto_inode=yes])

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

AC_ARG_ENABLE(lsm,
                [  --enable-lsm                   try to build LSM dependent modules [[autodetected]]],
                [   auto_lsm=no
                    AC_SUBST(lsm,$enableval) ],
                [   auto_lsm=yes])

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

AC_ARG_ENABLE(x-workaround,
              [  --disable-x-workaround         disable X server workaround where open(2) fails with -EINTR because of itimers are not honoured [[enabled]]],
              [ if test "$enableval" = "yes"; then
                    AC_SUBST(xhack,"-DTALPA_HAS_XHACK")
                fi
              ],
              [ AC_SUBST(xhack, "-DTALPA_HAS_XHACK")])

CFLAGS=

#
# Programs.
#
AC_PROG_CC
AC_CHECK_TOOL(MODULELINKER, ld, :)

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
$4
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

AC_MSG_CHECKING([for kernel architecture])
${CC} -Werror -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) ${srcdir}/tests/configure/kernarch.c -o tests/configure/kernarch
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
${CC} -Werror -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) ${srcdir}/tests/configure/kernversion.c -o tests/configure/kernversion
kern_version_code=`tests/configure/kernversion`
AC_MSG_RESULT([${kern_version_code}])
${RM} -f tests/configure/kernversion
AC_MSG_CHECKING([for kernel version string])
${CC} -Werror -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) ${srcdir}/tests/configure/kernrelease.c -o tests/configure/kernrelease
kern_uts_release=`tests/configure/kernrelease`
AC_MSG_RESULT([${kern_uts_release}])
${RM} -f tests/configure/kernrelease

AM_CONDITIONAL(KBUILD26, test $((kern_version_code)) -ge 132608)
# Test whether kbuild uses M= or SUBDIRS=, 2.6.8 was the first kernel to use M=
AM_CONDITIONAL(KBUILDUSEM, test $((kern_version_code)) -ge 132616)
# Set it to true for time being
AM_CONDITIONAL(BUILDLSM, test 1 -eq 1)

# Select interceptor to use for testing
case $testinterceptor in
    default)
        AC_SUBST(interceptor_module,vfshook)
        AC_SUBST(interceptor_name,VFSHookInterceptor)
#         if test $((kern_version_code)) -ge 132608; then
#             AC_SUBST(interceptor_module,lsm)
#             AC_SUBST(interceptor_name,LSMInterceptor)
#         else
#             AC_SUBST(interceptor_module,syscall)
#             AC_SUBST(interceptor_name,SyscallInterceptor)
#         fi
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

# Check for i_alloc_sem only for kernels older than
# 2.4.22 for 2.4 series, and older than 2.6.6 for 2.6
if test "$auto_inode" = "yes"; then
    if test $((kern_version_code)) -lt 132608; then
        # 2.4 kernels
        if test $((kern_version_code)) -lt 132118; then
            auto_inode=yes
        else
            auto_inode=no
        fi
    else
        # 2.6 kernels
        if test $((kern_version_code)) -lt 132614; then
            auto_inode=yes
        else
            auto_inode=no
        fi
    fi
fi

if test "$auto_inode" = "yes"; then
    TALPA_LOCATE_HEADER(linux/fs.h, $kernelhdrspath)
    AC_MSG_CHECKING([for i_alloc_sem inode struct member])
    ${EGREP} i_alloc_sem\; $TALPA_HEADER_LOCATION/linux/fs.h >/dev/null 2>&1
    if test $? -eq 0; then
        AC_MSG_RESULT([detected])
        AC_SUBST(inodeallocsem,"-DTALPA_HAS_INODE_ALLOC_SEM")
    else
        AC_MSG_RESULT([not detected])
    fi
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

AC_MSG_CHECKING([for appropriate build system])
if test $((kern_version_code)) -ge 132608; then
    AC_MSG_RESULT([2.6 build system detected])
    AC_SUBST(ko,ko)

    AC_SUBST(hidden,"-DTALPA_HIDDEN_SYSCALLS")

    # some 2.6 kernels do not export do_execve (vanilla >=2.6.10 and some vendor ones)
    AC_MSG_CHECKING([for syscallhook module execve support])
    if test -f $kerneldir/fs/exec.c; then
        ${EGREP} EXPORT_SYMBOL\\\(do_execve\\\)\; $kerneldir/fs/exec.c >/dev/null 2>&1
        if test $? -ne 0; then
            AC_SUBST(execve,"")
            AC_MSG_RESULT([not available])
        else
            AC_MSG_RESULT([available])
        fi
    else
        AC_SUBST(execve,"")
        AC_MSG_RESULT([not available])
    fi

    # Autodetect if we are running on 2.6.5 with backported sched.h
    if test $((kern_version_code)) -le 132613; then
        if test "$auto_tasknewtty" = "yes"; then
            TALPA_LOCATE_HEADER(linux/sched.h, $kernelhdrspath)
            TALPA_LOCATE_DIR(asm/mach-default, $kernelhdrspath)
            AC_MSG_CHECKING([for backported sched.h])
            ${CC} -Werror -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/tasktty.c -o /dev/null 1>/dev/null 2>&1
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

    # Autodetect if task_struct->signal was backported
    if test $((kern_version_code)) -lt 132620; then
        if test "$auto_signalbackport" = "yes"; then
            TALPA_LOCATE_HEADER(linux/sched.h, $kernelhdrspath)
            TALPA_LOCATE_DIR(asm/mach-default, $kernelhdrspath)
            AC_MSG_CHECKING([for backported task_struct->signal])
            ${CC} -Werror -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/tasksignal.c -o /dev/null 1>/dev/null 2>&1
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
            ${CC} -Werror -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/msecstojiffies.c -o /dev/null 1>/dev/null 2>&1
            if test $? -eq 0; then
                AC_MSG_RESULT([detected])
                AC_SUBST(jiffiesbackport,"-DTALPA_HAS_BACKPORTED_JIFFIES")
            else
                AC_MSG_RESULT([not detected])
            fi
        fi
    fi

    # Check whether to build LSM related modules
    AC_MSG_CHECKING([for LSM support])
    if test "$auto_lsm" = "yes"; then
        TALPA_LOCATE_HEADER(linux/autoconf.h, $kernelhdrspath, , , [quiet])
        ${CC} -Werror -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) ${srcdir}/tests/configure/lsm.c -o tests/configure/lsm
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

        if test $((kern_version_code)) -le 132617; then
            # Autodetect if LSM from 2.6.10 is backported to 2.6.9
            if test "$auto_lsm2610" = "yes"; then
                AC_MSG_CHECKING([for 2.6.10 LSM])
                ${CC} -Werror -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/lsm2610.c -o /dev/null 1>/dev/null 2>&1
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
                ${CC} -Werror -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/lsm266.c -o /dev/null 1>/dev/null 2>&1
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
                    ${CC} -Werror -pipe -D__KERNEL__ TALPA_INCLUDE_PATH($kernelhdrspath) -I$TALPA_DIR_LOCATION/asm/mach-default -c ${srcdir}/tests/configure/lsm265.c -o /dev/null 1>/dev/null 2>&1
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

    ${SED} s/@debug@/"${debug}"/ ${srcdir}/Makefile26.in >${srcdir}/Makefile
    ${SED} -i s/@newparent@/"${newparent}"/ ${srcdir}/Makefile
    ${SED} -i s/@inodeallocsem@/"${inodeallocsem}"/ ${srcdir}/Makefile
    ${SED} -i s/@tasknewtty@/"${tasknewtty}"/ ${srcdir}/Makefile
    ${SED} -i s/@rcubackport@/"${rcubackport}"/ ${srcdir}/Makefile
    ${SED} -i s/@signalbackport@/"${signalbackport}"/ ${srcdir}/Makefile
    ${SED} -i s/@jiffiesbackport@/"${jiffiesbackport}"/ ${srcdir}/Makefile
    ${SED} -i s/@buildlsm@/"${lsm}"/ ${srcdir}/Makefile
    ${SED} -i s/@lsm265@/"${lsm265}"/ ${srcdir}/Makefile
    ${SED} -i s/@lsm266@/"${lsm266}"/ ${srcdir}/Makefile
    ${SED} -i s/@lsm2610@/"${lsm2610}"/ ${srcdir}/Makefile
    ${SED} -i s/@hidden@/"${hidden}"/ ${srcdir}/Makefile
    ${SED} -i s/@execve@/"${execve}"/ ${srcdir}/Makefile
    ${SED} -i s/@xhack@/"${xhack}"/ ${srcdir}/Makefile

    ${SED} -i s/@debug@/"${debug}"/ ${srcdir}/tests/modules/Makefile
    ${SED} -i s/@inodeallocsem@/"${inodeallocsem}"/ ${srcdir}/tests/modules/Makefile
    ${SED} -i s/@tasknewtty@/"${tasknewtty}"/ ${srcdir}/tests/modules/Makefile
else
    AC_MSG_RESULT([2.4 build system detected])
    AC_SUBST(ko,o)

    # Check for hidden syscall table
    if test "$auto_hidden" = "yes"; then
        AC_MSG_CHECKING([for syscall table])
        if test -f $kerneldir/kernel/ksyms.c; then
            ${EGREP} EXPORT_SYMBOL\\\(sys_call_table\\\)\; $kerneldir/kernel/ksyms.c >/dev/null 2>&1
            if test $? -ne 0; then
                AC_MSG_RESULT([hidden])
                AC_SUBST(hidden,"-DTALPA_HIDDEN_SYSCALLS")
            else
                AC_MSG_RESULT([exported])
            fi
        else
            syscalls_unknown=yes
            AC_MSG_RESULT([skipped])
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

AC_SUBST(kernelincludes,TALPA_INCLUDE_PATH($kernelhdrspath))

#
# ...Should we build?
#
else
    # define these two to please autoconf
    AM_CONDITIONAL(KBUILD26, test 1 -eq 1)
    AM_CONDITIONAL(KBUILDUSEM, test 0 -eq 1)
    AM_CONDITIONAL(BUILDLSM, test 1 -eq 1)
fi


#
# Output.
#
AC_OUTPUT([makefile clients/Makefile tests/Makefile tests/modules/makefile])

if test "$syscalls_unknown" = "yes"; then
    echo -e "\nFailed to autodetect syscall table status - defaulting to exported.\nUse separate --with-kernel and --with-kernel-include, or set --enable-hidden-syscall-table.\n"
fi

#
# End of configure.ac
#
