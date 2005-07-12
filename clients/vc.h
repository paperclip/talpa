/*
 * TALPA test program
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
#ifndef H_VC
#define H_VC

/* Vetting client "library" */

#include "../include/talpa-vettingclient.h"

int vc_init(unsigned int group, unsigned int timeout_ms);
int vc_exit(int handle);
struct TalpaPacket_VettingDetails* vc_get(int handle);
struct TalpaPacket_VettingDetails* vc_poll(int handle, unsigned int ms);
void vc_release(int handle, struct TalpaPacket_VettingDetails* packet);
int vc_respond(int handle, struct TalpaPacket_VettingDetails* packet, ETalpaProtocolResponse response);

int vc_stream_length(int handle);
int vc_stream_seek(int handle, unsigned int offset, int mode);
int vc_stream_read(int handle, void *buffer, size_t size);
int vc_stream_write(int handle, void *buffer, size_t size);
int vc_stream_unlink_file(int handle);
int vc_stream_truncate(int handle, unsigned int length);

int vc_scan_stream(int handle);

#define vc_file_frag(packet) ((struct TalpaPacketFragment_FileDetails *)(((char *)packet) + sizeof(struct TalpaPacket_VettingDetails)))
#define vc_file_name(filefrag) (((char *)filefrag) + sizeof(struct TalpaPacketFragment_FileDetails))

#define vc_filesystem_frag(packet) ((struct TalpaPacketFragment_FilesystemDetails *)(((char *)packet) + sizeof(struct TalpaPacket_VettingDetails)))
#define vc_filesystem_dev(fsfrag) (((char *)fsfrag) + sizeof(struct TalpaPacketFragment_FilesystemDetails))

#endif
