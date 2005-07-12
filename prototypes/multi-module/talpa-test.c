/* 
 * talpa-test.c
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

typedef const char*(*talpa_mesg_t)(void);
extern const char* talpa_core_mesg(void);

static int __init talpa_test_init(void)
{
    const char* hello_msg = 0;


    printk(KERN_INFO "talpa-test.o: TALPA interceptor\n");
    printk(KERN_INFO "talpa-test.o: TALPA interceptor\n");
    hello_msg = talpa_core_mesg();
    printk(KERN_INFO "talpa-test.o: TALPA interceptor\n");
    printk(hello_msg);
    return 0;
}

static void __exit talpa_test_exit(void)
{
    return;
}

/*
 *
 * Module information.
 *
 */

MODULE_AUTHOR("Barry Pearce <barry.pearce@sophos.com>");
MODULE_DESCRIPTION("TALPA Filesystem Interceptor Test Module");
MODULE_LICENSE("GPL");

EXPORT_NO_SYMBOLS;

module_init(talpa_test_init);
module_exit(talpa_test_exit);

/*
 * End of talpa-test.c
 */
