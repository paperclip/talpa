/*
 * cache.h
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
#ifndef H_CACHE
#define H_CACHE


#include "common/locking.h"
#include "common/list.h"
#include "cache/icache.h"
#include "configurator/iconfigurable.h"

/*
 * Configuration structures
 */


#define CACHE_CFGDATASIZE       (16)
#define CACHE_STATDATASIZE      (160)
#define CACHE_FSCFGDATASIZE     (128)
#define CACHE_PARAMSCFGDATASIZE (64)

typedef struct {
    char    name[CACHE_CFGDATASIZE];
    char    value[CACHE_CFGDATASIZE];
} CacheConfigData;

typedef struct {
    char    name[CACHE_CFGDATASIZE];
    char    value[CACHE_STATDATASIZE];
} CacheStatisticsData;

typedef struct {
    char    name[CACHE_CFGDATASIZE];
    char    value[CACHE_FSCFGDATASIZE];
} CacheFSConfigData;

typedef struct {
    char    name[CACHE_CFGDATASIZE];
    char    value[CACHE_PARAMSCFGDATASIZE];
} CacheParamsConfigData;

typedef struct
{
    talpa_list_head head;
    char*           string;
    unsigned int    len;
} CacheConfigObject;

struct CacheEntry
{
    int32_t    device;
    int32_t    inode;
};

typedef talpa_rw_lock_t talpa_cache_lock_t;

#define TALPA_CACHE_UNLOCKED     TALPA_RW_UNLOCKED
#define talpa_cache_lock_init    talpa_rw_init
#define talpa_cache_read_lock    talpa_read_lock
#define talpa_cache_read_unlock  talpa_read_unlock
#define talpa_cache_write_lock   talpa_write_lock
#define talpa_cache_write_unlock talpa_write_unlock

typedef struct tag_Cache
{
    ICache                  i_ICache;
    IConfigurable           i_IConfigurable;
    void                    (*delete)(struct tag_Cache* object);
    bool                    mEnabled;

    talpa_cache_lock_t      mCacheLock;
    unsigned int            mCacheBytes;
    struct CacheEntry*      mCache;
    unsigned int            mSetSize;
    unsigned int            mEntries;
    unsigned int            mPrime;
    unsigned int            mReplacement;
    unsigned int            mHits;
    unsigned int            mMisses;
    unsigned int            mFill;

    talpa_rcu_lock_t        mConfigLock;
    talpa_mutex_t           mConfigSerialize;
    talpa_list_head         mFilesystems;
    char*                   mFilesystemsSet;

    PODConfigurationElement mConfig[5];
    CacheConfigData         mStateConfigData[1];
    CacheStatisticsData     mStatisticsData[1];
    CacheFSConfigData       mFSConfigData[1];
    CacheParamsConfigData   mParamsConfigData[1];

} Cache;

/*
 * Object Creators.
 */
Cache* newCache(void);





#endif

/*
 * End of cache.h
 */

