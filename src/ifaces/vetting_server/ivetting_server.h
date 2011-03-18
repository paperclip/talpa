/*
 * ivetting_server.h
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
#ifndef H_IVETTINGSERVER
#define H_IVETTINGSERVER

#include <linux/wait.h>

#include "common/locking.h"
#include "common/list.h"
#include "intercept_filters/ievaluation_report.h"
#include "personality/ipersonality.h"
#include "process_and_thread/ithreadinfo.h"
#include "filesystem/ifile.h"
#include "filesystem/ifile_info.h"
#include "filesystem/ifilesystem_info.h"
#include "platform/glue.h"


#include "talpa-vettingclient.h"

/*
 * Internal structures
 */

typedef talpa_simple_lock_t talpa_group_lock_t;

#define TALPA_GROUP_UNLOCKED(lockname)    TALPA_SIMPLE_UNLOCKED(lockname)
#define talpa_group_lock_init   talpa_simple_init
#define talpa_group_lock        talpa_simple_lock
#define talpa_group_unlock      talpa_simple_unlock

typedef struct
{
    talpa_group_lock_t  lock;
    atomic_t            numClients;
    wait_queue_head_t   clientWaitQueue;
    talpa_list_head     intercepted;
} VettingGroup;

typedef struct
{
    talpa_list_head                     head;
    atomic_t                            refcnt;
    wait_queue_head_t                   interceptedWaitQueue;
    uint32_t                            vettingID;
    atomic_t                            complete;
    unsigned long                       lastActivity;
    bool                                extendedInfoRequested;
    bool                                responseRequired;

    IEvaluationReport*                  report;
    IThreadInfo*                        threadInfo;
    IPersonality*                       userInfo;
    IFileInfo*                          fileInfo;
    IFilesystemInfo*                    filesystemInfo;

    struct TalpaProtocolHeader*         vettingDetails;
    struct TalpaPacket_ExtDetailsOnly*  extendedInfo;
    struct TalpaProtocolHeader*         packet;

    /* Stream server support */
    IFile*                              file;
    atomic_t                            reopen;
    struct talpa_completion             reopenCompletion;
    bool                                externalOperation;
} VettingDetails;

typedef struct
{
    talpa_list_head         head;
    VettingClientID         id;
    struct task_struct*     process;
    atomic_t                registered;
    unsigned long           flags;
    atomic_t                vetting;
    uint32_t                groupID;
    VettingGroup            *group;
    uint32_t                timeout_ms;
    uint32_t                currentVettingID;
    VettingDetails          *vettingDetails;
    bool                    extDetailsRequested;
    struct TalpaPacket_FAIL response;
    void*                   private;

    /* Stream server support */
    atomic_t                            instream;
    unsigned int                        streamSize;
    struct TalpaPacket_StreamData*      stream;
} VettingClient;

/*
 * IVettingServer
 */

typedef struct
{
    unsigned int                (*queryMinPacketSize)   (const void* self);
    unsigned int                (*queryMaxPacketSize)   (const void* self);
    unsigned int                (*queryMinStreamPacket) (const void* self);
    unsigned int                (*queryMaxStreamPacket) (const void* self);
    VettingClient*              (*initializeClient)     (void* self);
    void                        (*destroyClient)        (void* self, VettingClient* client);
    struct TalpaProtocolHeader* (*registerClient)       (void* self, VettingClient* client, struct TalpaPacket_Register* packet);
    struct TalpaProtocolHeader* (*deregisterClient)     (void* self, VettingClient* client, struct TalpaPacket_Deregister* packet);
    struct TalpaProtocolHeader* (*processPacket)        (void* self, VettingClient* client, struct TalpaProtocolHeader* packet);
    struct TalpaProtocolHeader* (*setWaitTimeout)       (const void* self, VettingClient* client, struct TalpaPacket_SetWaitTimeout* packet);
    bool                        (*peekVettingQueue)     (const void* self, VettingClient* client);
    struct TalpaProtocolHeader* (*obtainVettingDetails) (void* self, VettingClient* client);
    void                        (*releaseVettingDetails)(const void* self, VettingClient* client);
    struct TalpaProtocolHeader* (*vettingResponse)      (void* self, VettingClient* client, struct TalpaPacket_VettingResponse* packet);
    struct TalpaProtocolHeader* (*streamLength)         (const void* self, VettingClient* client);
    struct TalpaProtocolHeader* (*streamSeek)           (void* self, VettingClient* client, struct TalpaPacket_StreamSeek* packet);
    struct TalpaProtocolHeader* (*streamRead)           (void* self, VettingClient* client, struct TalpaPacket_StreamRead* packet);
    struct TalpaProtocolHeader* (*streamWrite)          (void* self, VettingClient* client, struct TalpaPacket_StreamWrite* packet);
    struct TalpaProtocolHeader* (*streamReadAt)         (void* self, VettingClient* client, struct TalpaPacket_StreamReadAt* packet);
    struct TalpaProtocolHeader* (*streamWriteAt)        (void* self, VettingClient* client, struct TalpaPacket_StreamWriteAt* packet);
    struct TalpaProtocolHeader* (*streamUnlinkFile)     (void* self, VettingClient* client, struct TalpaPacket_StreamUnlinkFile* packet);
    struct TalpaProtocolHeader* (*streamTruncate)       (void* self, VettingClient* client, struct TalpaPacket_StreamTruncate* packet);

    /*
     *  Object supporting this interface instance.
     */
    void* object;
    void  (*delete)               (void* self);
} IVettingServer;

#endif

/*
 * End of ivetting_server.h
 */

