/*
 * device_driver_vetting_client.h
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
#ifndef H_IDEVICEDRIVERVETTINGCLIENT
#define H_IDEVICEDRIVERVETTINGCLIENT


#include "system_interfaces/idevice_file.h"
#include "configurator/iconfigurable.h"
#include "vetting_server/ivetting_server.h"



struct DDVC_Stream
{
    unsigned char*      buf;
    unsigned char*      ptr;
    unsigned int        total;
    unsigned int        remain;
};

struct DDVC_State
{
    atomic_t                    reading;
    struct DDVC_Stream          stream;
    unsigned int                mininsize;
    unsigned int                maxinsize;
    struct TalpaProtocolHeader* packet;
};

/*
 * Configuration structures
 */

#define DDVETTINGCLIENT_CFGDATASIZE      (sizeof(char) * 16)

typedef struct {
    char    name[DDVETTINGCLIENT_CFGDATASIZE];
    char    value[DDVETTINGCLIENT_CFGDATASIZE];
} DDVettingClientConfigData;


typedef struct tag_DeviceDriverVettingClient
{
    IDeviceFile                 i_IDeviceFile;
    IConfigurable               i_IConfigurable;
    void                        (*delete)(struct tag_DeviceDriverVettingClient* object);
    IVettingServer*             mServer;
    PODConfigurationElement     mConfig[2];
    DDVettingClientConfigData   mConfigData[1];
} DeviceDriverVettingClient;


/*
 * Object Creators.
 */
DeviceDriverVettingClient* newDeviceDriverVettingClient(IVettingServer* server);

#endif

/*
 * End of device_driver_vetting_client.h
 */

