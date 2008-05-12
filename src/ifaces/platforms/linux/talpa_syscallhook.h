/*
 * talpa_syscallhook.h
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004 Sophos Plc, Oxford, England.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License Version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if not,
 * write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */
#ifndef H_TALPASYSCALLHOOK
#define H_TALPASYSCALLHOOK


#define TALPA_SYSCALLHOOK_IFACE_VERSION (1)

/*
 * All strings are in userspace except for execve.
 */

struct talpa_syscall_operations
{
    long    (*open_post)    (unsigned int fd);
    void    (*close_pre)    (unsigned int fd);
    long    (*uselib_pre)   (const char* library);
    int     (*execve_pre)   (const char* name);
    long    (*mount_pre)    (char* dev_name, char* dir_name, char* type, unsigned long flags, void* data);
    void    (*mount_post)   (int err, char* dev_name, char* dir_name, char* type, unsigned long flags, void* data);
    void    (*umount_pre)   (char* name, int flags);
    void    (*umount_post)  (int err, char* name, int flags);
};

/*
 * Returns an integer describing version of struct talpa_syscall_operations.
 * Users must check before registering that the versions match.
 */
unsigned int talpa_syscallhook_interface_version(void);

/*
 * Register yourself if you want talpa_syscallhook to call you.
 * You must define all the hooks which are enabled at run time
 * because talpa_syscallhook does no checking!
 */
int talpa_syscallhook_register(struct talpa_syscall_operations* ops);

/*
 * Unregister may sleep until the last caller exits.
 */
void talpa_syscallhook_unregister(struct talpa_syscall_operations* ops);

/*
 * Call when you want to write to potentialy read-only kernel
 * memory. modify_finish must be called after modifications are
 * done. Calls cannot be nested.
 */
void talpa_syscallhook_modify_start(void);

/*
 * Call when you are done writing to potentialy read-only kernel
 * memory.
 */
void talpa_syscallhook_modify_finish(void);

#endif

/*
 * End of talpa_syscallhook.h
 */
