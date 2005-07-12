/* 
 * sockmod.c
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
 * (c) Copyright Sophos PLC 2003
 */

#define __KERNEL__
#define MODULE

/* 
 * Standard headers for LKMs 
 */
#include <linux/modversions.h> 
#include <linux/module.h>  

/*
 * Console Printing.
 */
#include <linux/tty.h>

#include <asm/uaccess.h>

#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/un.h>

/* 
 * Initialize the LKM 
 */
int init_module()
{
    int retcode;
    struct socket*  s;
    struct sockaddr_un sa = { PF_UNIX, "/dev/sockcomm" };

    struct msghdr msg;
    struct iovec iov;
    unsigned char cbuf[64];
    mm_segment_t    oldfs;

      
    /*
     * Create the socket.
     */
     console_print("SOCKMOD: *** Creating Socket...\n");
    if ((retcode = sock_create(PF_UNIX, SOCK_STREAM, 0, &s))  < 0)
    {
        console_print("SOCKMOD: *** Failed to create Socket...\n");
        return 11;
    }


    /*
     * Connect it to make it accessible.
     */
     console_print("SOCKMOD: *** Connecting Socket...\n");
    if ((retcode = s->ops->connect(s, (struct sockaddr*)&sa, sizeof(struct sockaddr_un), 0)) < 0)
    {
        console_print("SOCKMOD: *** Failed to connect Socket...\n");
        sock_release(s);
        return 12;
    }

    /*
     * Talk to the dark side!
     */
     console_print("SOCKMOD: *** send data to  Socket...\n");

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    iov.iov_base = cbuf;
    memcpy(cbuf, "Hello!", 7);
    iov.iov_len = 7;
    
    msg.msg_control = 0;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;


    oldfs = get_fs(); set_fs(KERNEL_DS);
    retcode = sock_sendmsg(s, &msg, 7);
    set_fs(oldfs);


    if (retcode < 0)
    {
        console_print("SOCKMOD: *** failed to send data...\n");
        sprintf(cbuf, "retcode: %d\n", retcode);
        console_print(cbuf);

        sock_release(s);

        return 13;
    }

    console_print("SOCKMOD: *** Send DATA \n");
    sprintf(cbuf, "retcode: %d\n", retcode);
    console_print(cbuf);


                
    console_print("SOCKMOD: *** Closing Socket...\n");
    sock_release(s); 

    return 0;
}


void cleanup_module()
{
    return;
}


/*
 * End of sockmod.c
 */
