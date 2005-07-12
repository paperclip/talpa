/* 
 * socksrv.c
 *
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
#include <errno.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define EVER ;;

int main()
{
    int newconn;
    int retcode;
    int s;
    int recvd_len;
    struct sockaddr_un sa = { PF_UNIX, "/dev/sockcomm" };
    struct sockaddr_un    sap;
    socklen_t sal;

    struct msghdr msg;
    unsigned char	buffer[1024];
    unsigned char	buffer2[1024];
    struct iovec  iov;
    


    /*
     * Create the socket.
     */
    printf("Creating Socket\n");
    fflush(stdout);
    if ((s = socket(PF_UNIX, SOCK_STREAM, 0))  < 0)
    {
        printf("Create failed. %d %s\n", errno, strerror(errno));
        exit(retcode);
    }


    /*
     * Bind it to make it accessible.
     */
    printf("Unlinking...\n");
    fflush(stdout);
    unlink("/dev/sockcomm");
    printf("Binding socket...\n");
    fflush(stdout);
    if ((retcode = bind(s, (struct sockaddr*)&sa, sizeof(struct sockaddr))) < 0)
    {
        printf("Bind failed. %d %s\n", errno, strerror(errno));
        exit(retcode);
    }

    /*
     * Listen on it - could be as low as five!
     */
    printf("Listening on socket...\n");
    fflush(stdout);
    if ((retcode = listen(s, SOMAXCONN)) < 0)
    {
        printf("Listen failed. %d %s\n", errno, strerror(errno));
        exit(retcode);
    }

    for (EVER)
    {
        printf("Awaiting connection...\n");
        fflush(stdout);
        /*
         * Accept a connection.
         */
        newconn = accept(s, (struct sockaddr*)&sap, &sal); 

        printf("Got connection...\n");
        fflush(stdout);

        /*
         * Get the message!
         */
        msg.msg_name = 0;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_iov->iov_base = buffer2;
        msg.msg_iov->iov_len = 1024;
        msg.msg_control = buffer;
        buffer[0] = 0;
        msg.msg_controllen = 1024;
        msg.msg_flags = 0;
        
        printf("receiving message...\n");
        fflush(stdout);
        if ((recvd_len = recvmsg(newconn, &msg, 0)) > -1)
        {
            printf("RECVD: %d\n", recvd_len);
            printf("RECVD: %d %s\n", msg.msg_iovlen, msg.msg_iov->iov_base);
            fflush(stdout);
        }
        else
       {
            printf("Receive failed %d %s\n", errno, strerror(errno));
            fflush(stdout);               
       }
        
        printf("closing connection...\n");
        fflush(stdout);
        close(newconn);
    }

    return 0;
}

/*
 * End of socksrv.c
 */
