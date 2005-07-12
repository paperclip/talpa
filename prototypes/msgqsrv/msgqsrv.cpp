/*
 * msgqsrv.c
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
 * (c) Copyright Sophos PLC 2004
 */
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <errno.h>

#include <iostream>

#define EVER ;;

typedef struct
    {
        long mtype;
        char mtext[1024];
    } KernelMsg;

int main()
{
    KernelMsg recvBuffer;
    ssize_t   recvSize;

    /*
     * Receive message...
     */
    for (EVER)
    {
        std::cout << "Listening for message..." << std::flush;

        recvSize = msgrcv(1001, reinterpret_cast<struct msgbuf*>(&recvBuffer), 1024, 1, 0);
        if (recvSize > -1)
        {
            std::cout << "Done" << std::endl
                      << "RECVD: [" << recvBuffer.mtext << "]" << std::endl;
        }
        else
        {

            std::cout << "Failed." << std::endl
                      << "Error: " << errno << "/" << strerror(errno) << std::endl;
            break;
        }
    }

    return 0;
}

/*
 * End of msgqsrv.c
 */
