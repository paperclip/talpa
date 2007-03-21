/*
 * talpa-vettingclient.h
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

#ifndef H_TALPAVETTINGCLIENT
#define H_TALPAVETTINGCLIENT

#ifndef __KERNEL__
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define TALPA_PROTOCOL_VERSION 4

typedef unsigned long VettingClientID;

/*
 * Enumerations for packet types and special fields values
 */

typedef enum
{
    TALPA_PKT_OK = 0x00000,
    TALPA_PKT_FAIL = 0x00001,
    TALPA_PKT_REG = 0x00010,
    TALPA_PKT_DEREG = 0x00020,
    TALPA_PKT_SETVETTIMEOUT = 0x00040,
    TALPA_PKT_OBTAINVETDET = 0x00100,
    TALPA_PKT_FILEDETAIL = 0x01000,
    TALPA_PKT_FILESYSTEMDETAIL = 0x02000,
    TALPA_PKT_EXTVETDETAILONLY = 0x04000,
    TALPA_PKT_EXTFILEDETAIL = 0x05000,
    TALPA_PKT_EXTFILESYSTEMDETAIL = 0x06000,
    TALPA_PKT_VETRESPONSE = 0x10000,
    TALPA_PKT_STREAMDATA = 0x100000,
    TALPA_PKT_STREAMLENGTH = 0x100001,
    TALPA_PKT_STREAMSEEK = 0x100002,
    TALPA_PKT_STREAMREAD = 0x100004,
    TALPA_PKT_STREAMWRITE = 0x100008,
    TALPA_PKT_STREAMREADAT = 0x100014,
    TALPA_PKT_STREAMWRITEAT = 0x100018,
    TALPA_PKT_STREAMUNLINKFILE = 0x100020,
    TALPA_PKT_STREAMTRUNCATE = 0x100040
} ETalpaProtocolPacketType;

typedef enum
{
    TALPA_DONTRESPOND = 0x0,
    TALPA_RESPOND
} ETalpaProtocolResponseType;

typedef enum
{
    TALPA_OPEN = 0x0,
    TALPA_CLOSE,
    TALPA_EXEC
} ETalpaProtocolFileOperation;

typedef enum
{
    TALPA_MOUNT = 0x0,
    TALPA_UMOUNT
} ETalpaProtocolFilesystemOperation;

typedef enum
{
    TALPA_ALLOW = 0x0,
    TALPA_DENY,
    TALPA_TIMEOUT,
    TALPA_ERROR,
    TALPA_REQEXTDETAIL
} ETalpaProtocolResponse;


/*
 * Core structures
 */

struct TalpaPacketFragment_FileDetails
{
    uint32_t    operation;
    uint32_t    flags;
    uint32_t    mode;
                /* string follows */
} __attribute__ ((packed));

struct TalpaPacketFragment_FilesystemDetails
{
    uint32_t    operation;
    uint32_t    fstype_offset;
    uint32_t    device_offset;
    uint32_t    mountpoint_offset;
                /* strings follow */
} __attribute__ ((packed));

struct TalpaPacketFragment_ExtDetails
{
    uint32_t    controllingTTY;
    uint32_t    envLength;
                /* env blob follows */
} __attribute__ ((packed));

/*
 * Packet structures
 */

struct TalpaProtocolHeader
{
    uint32_t    type;
    uint32_t    version;
    uint32_t    payloadLength;
} __attribute__ ((packed));

struct TalpaPacket_OK
{
    struct TalpaProtocolHeader  header;
} __attribute__ ((packed));

struct TalpaPacket_FAIL
{
    struct TalpaProtocolHeader  header;
    int32_t                     errorCode;
} __attribute__ ((packed));

struct TalpaPacket_Register
{
    struct TalpaProtocolHeader  header;
    uint32_t                    group;
} __attribute__ ((packed));

struct TalpaPacket_Deregister
{
    struct TalpaProtocolHeader  header;
} __attribute__ ((packed));

struct TalpaPacket_SetWaitTimeout
{
    struct TalpaProtocolHeader  header;
    uint32_t                    timeout_ms;
} __attribute__ ((packed));

struct TalpaPacket_ObtainVettingDetails
{
    struct TalpaProtocolHeader  header;
} __attribute__ ((packed));

struct TalpaPacket_VettingResponse
{
    struct TalpaProtocolHeader  header;
    uint32_t                    vettingID;
    uint32_t                    response;
    uint32_t                    errorCode;
} __attribute__ ((packed));

struct TalpaPacket_VettingDetails
{
    struct TalpaProtocolHeader  header;
    uint32_t                    vettingID;
    uint32_t                    responseReqd;
    uint32_t                    extOffset;
    uid_t                       uid;
    gid_t                       gid;
    uid_t                       euid;
    gid_t                       egid;
    uid_t                       fsuid;
    pid_t                       processID;
    pid_t                       threadID;
    uint32_t                    rootdir_len;
                                /* file/filesystem fragment follows, ext details optional */
} __attribute__ ((packed));

struct TalpaPacket_ExtDetailsOnly
{
    struct TalpaProtocolHeader              header;
    struct TalpaPacketFragment_ExtDetails   extDetails;
} __attribute__ ((packed));

struct TalpaPacket_StreamLength
{
    struct TalpaProtocolHeader  header;
} __attribute__ ((packed));

struct TalpaPacket_StreamSeek
{
    struct TalpaProtocolHeader  header;
    int64_t                     offset;
    uint32_t                    mode;
} __attribute__ ((packed));

struct TalpaPacket_StreamRead
{
    struct TalpaProtocolHeader  header;
    uint32_t                    size;
} __attribute__ ((packed));

struct TalpaPacket_StreamReadAt
{
    struct TalpaProtocolHeader  header;
    uint32_t                    size;
    int64_t                     offset;
    uint32_t                    mode;
} __attribute__ ((packed));

struct TalpaPacket_StreamData
{
    struct TalpaProtocolHeader  header;
    uint64_t                    size;
} __attribute__ ((packed));

struct TalpaPacket_StreamWrite
{
    struct TalpaProtocolHeader  header;
    uint32_t                    size;
} __attribute__ ((packed));

struct TalpaPacket_StreamWriteAt
{
    struct TalpaProtocolHeader  header;
    uint32_t                    size;
    int64_t                     offset;
    uint32_t                    mode;
} __attribute__ ((packed));

struct TalpaPacket_StreamUnlinkFile
{
    struct TalpaProtocolHeader  header;
} __attribute__ ((packed));

struct TalpaPacket_StreamTruncate
{
    struct TalpaProtocolHeader  header;
    uint64_t                    length;
} __attribute__ ((packed));

#ifdef __cplusplus
}
#endif


#define TLPVCIOC_REGISTER       _IOW ( 0xff,     0,      struct TalpaPacket_Register )
#define TLPVCIOC_DEREGISTER     _IOW ( 0xff,     1,      struct TalpaPacket_Deregister )
#define TLPVCIOC_SETWAITTIMEOUT _IOW ( 0xff,     2,      struct TalpaPacket_SetWaitTimeout )
/* Maximum packet size client can send */
#define TLPVCIOC_GETBUFFERSIZE  _IO  ( 0xff,     3 )
/* Maximum stream packet size client can receive */
#define TLPVCIOC_GETSTREAMSIZE  _IO  ( 0xff,     4 )

#endif

/*
 * End of talpa-vettingclient.h
 */
