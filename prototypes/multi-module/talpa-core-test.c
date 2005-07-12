/* 
 * talpa-core-test.c
 *
 * KERNEL MODULE!
 *
 * WARNING WARNING WARNING
 * This source code has been produced for PROTOTYPING ONLY.
 * It is of poor quality, intended merely to prove technical feasibility.
 * It MUST NOT be used in a production system in any form whatsoever.
 * WARNING WARNING WARNING
 *
 *
 * Barry Pearce
 * (c) Copyright Sophos PLC 2004
 */

/* 
 * Standard headers for LKMs 
 */
#include <linux/module.h>  


const char* talpa_core_mesg(void)
{
    printk(KERN_INFO "talpa-core.o: mesg()\n");
    return "Boing!\n";
}



static int __init talpa_core_init(void)
{
    printk(KERN_INFO "talpa-core.o: TALPA core module\n");
    printk(talpa_core_mesg());
    return 0;
}

static void __exit talpa_core_exit(void)
{
    return;
}

/*
 *
 * Module information.
 *
 */

MODULE_AUTHOR("Barry Pearce <barry.pearce@sophos.com>");
MODULE_DESCRIPTION("TALPA Filesystem Interceptor Core Module");
MODULE_LICENSE("GPL");

module_init(talpa_core_init);
module_exit(talpa_core_exit);

EXPORT_SYMBOL_NOVERS(talpa_core_mesg);


/*
 * End of talpa-core-test.c
 */
