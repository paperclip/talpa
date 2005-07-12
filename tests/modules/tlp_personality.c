/*
 * tlp-personality.c
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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <asm/errno.h>

#include "tlp-test.h"


#include "common/bool.h"
#define TALPA_SUBSYS "personalitytest"
#include "common/talpa.h"

#include "components/services/linux_personality_impl/linux_personality.h"

int talpa_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long parm)
{
    int ret = -ENOTTY;

    struct talpa_personality tpers;
    LinuxPersonality *pers;

    switch ( cmd )
    {
        case TALPA_TEST_PERSONALITY:
            ret = copy_from_user(&tpers, (void *)parm, sizeof(struct talpa_personality));
            if ( !ret )
            {
                pers = newLinuxPersonality();
                if ( pers )
                {
                    tpers.uid = pers->i_IPersonality.uid(pers);
                    tpers.euid = pers->i_IPersonality.euid(pers);
                    tpers.gid = pers->i_IPersonality.gid(pers);
                    tpers.egid = pers->i_IPersonality.egid(pers);
                    ret = copy_to_user((void *)parm,&tpers,sizeof(struct talpa_personality));
                    if ( ret )
                    {
                        err("copy_to_user!");
                    }
                    pers->delete(pers);
                }
                else
                {
                    err("Failed to create IPersonality!");
                    ret = -EINVAL;
                }
            }
            else
            {
                err("copy_from_user!");
            }
            break;
    }

    return ret;
}

struct file_operations talpa_fops =
{
    owner:  THIS_MODULE,
    ioctl:  talpa_ioctl

};

static int __init talpa_test_init(void)
{
    int ret;

    ret = register_chrdev(TALPA_MAJOR, TALPA_DEVICE, &talpa_fops);

    if ( ret )
    {
        err("Failed to register TALPA Test character device!");
        return ret;
    }

    return 0;
}

static void __exit talpa_test_exit(void)
{
    int ret;

    ret = unregister_chrdev(TALPA_MAJOR, TALPA_DEVICE);

    if ( ret )
    {
        err("Hmmmmmm... very strange things are happening!");
    }
}

/*
 *
 * Module information.
 *
 */
MODULE_AUTHOR("Sophos Plc");
MODULE_DESCRIPTION("TALPA Filesystem Interceptor Test Module");
MODULE_LICENSE("GPL");

module_init(talpa_test_init);
module_exit(talpa_test_exit);

