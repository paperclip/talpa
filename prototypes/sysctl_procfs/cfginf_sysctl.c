/* hello.c
 *
 * "Hello, world" - the loadable kernel module version.
 *
 * Compile this with
 *
 *          gcc -c hello.c -Wall
 */

/* Declare what kind of code we want from the header files */
#define __KERNEL__         /* We're part of the kernel */
#define MODULE             /* Not a permanent part, though. */

/* Standard headers for LKMs */
#include <linux/modversions.h>
#include <linux/module.h>
#include <linux/sysctl.h> /* Sysctl interface */
#include <linux/tty.h>      /* console_print() interface */
#include <asm/uaccess.h>

// #inclue "sophosctl.h"

#define MODULE_VERSION "1.0"
#define MODULE_NAME "sophos_sysctl_test"


static int my_ctl_handler (int test, ctl_table *table, int *name, int nlen,
                           void *oldval, size_t *oldlenp,
                           void *newval, size_t newlen,
                           void **context)
{
    char* bonk;
    size_t size;
    if (oldval)
    {
    
        bonk = table->data;
        size = (sizeof(char) * strlen(bonk));
        copy_to_user(oldval, bonk, size);
        put_user(size, oldlenp);
    }
    if (newval) {
        copy_from_user(table->data, newval, newlen);
    }
    return 1;
}


static int my_ctl_handler1 (ctl_table *table, int *name, int nlen,
                           void *oldval, size_t *oldlenp,
                           void *newval, size_t newlen,
                           void **context)
{
    return my_ctl_handler(1,table,name,nlen,oldval,oldlenp,newval,newlen,context);
}
static int my_ctl_handler2 (ctl_table *table, int *name, int nlen,
                           void *oldval, size_t *oldlenp,
                           void *newval, size_t newlen,
                           void **context)
{
    return my_ctl_handler(2,table,name,nlen,oldval,oldlenp,newval,newlen,context);
}

static int my_proc_dostring(ctl_table *ctl,
                            int write,
                            struct file *filp,
                            void *buffer,
                            size_t *lenp)
{
    console_print("my_proc_dostring\n");
    return proc_dostring(ctl,write,filp,buffer,lenp);
}
    
    

enum { CTL_SOPHOS = 1329, MYTEST_BUFFER = 1, CTL_TEST = 1330 };
static char buffer[128];
static char buffer2[128];
        
static ctl_table my_inner_ctl_table[] = {
    {
        MYTEST_BUFFER,
        "MagicString",
        buffer2,
        sizeof(char) * 128,
        0666,
        NULL,
        &my_proc_dostring,
        &my_ctl_handler2,
    },
    {0}
};

static ctl_table my_ctl_table[] = {
    {
        CTL_SOPHOS,
        "sophos",
        0,
        0,
        0,
        my_inner_ctl_table,
    },

    {
        CTL_TEST,
        "SophosMagic",
        buffer,
        sizeof(char) * 128,
        0666,
        NULL,
        &my_proc_dostring,
        &my_ctl_handler1,
    },
    {0}
};

static struct ctl_table_header *my_table_header;

/* Initialize the LKM */
int init_module()
{
    console_print("Starting up\n");
    
    sprintf(buffer,"bonk!1");
    sprintf(buffer2,"bonk!2");
    
  if (!(my_table_header = register_sysctl_table(my_ctl_table, 0)))
    return EPERM;

/* If we return a non zero value, it means that
* init_module failed and the LKM can't be loaded
*/
  return 0;
}


/* Cleanup - undo whatever init_module did */
void cleanup_module()
{
  if (my_table_header)
    unregister_sysctl_table(my_table_header);
  
  console_print("Short is the life of an LKM\n");
}
