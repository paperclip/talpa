/*
 * getPath.h
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2013 Sophos Limited, Oxford, England.
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

#include <linux/fs.h>
#include <linux/slab.h>

#if defined __GFP_NOWARN && defined __GFP_NORETRY
# define TALPA_MAX_ORDER 3
#else
# define TALPA_MAX_ORDER 0
#endif

char* getPath(struct vfsmount* root, char** pathPtr, int* mnt_orderPtr, size_t* path_size);
