/*
 * linux_Personality_factoryimpl.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2011 Sophos Limited, Oxford, England.
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
#include "linux_personality_factoryimpl.h"
#include "linux_personality.h"

/*
 * Forward declare implementation methods.
 */
static inline IPersonality* newPersonality(const void* self);
static void deleteLinuxPersonalityFactoryImpl(struct tag_LinuxPersonalityFactoryImpl* object);

/*
 * Singleton object.
 */
static LinuxPersonalityFactoryImpl GL_object =
    {
        {
            newPersonality,
            &GL_object,
            (void (*)(const void*))deleteLinuxPersonalityFactoryImpl
        },
        deleteLinuxPersonalityFactoryImpl,
    };


/*
 * Object creation/destruction.
 */
inline LinuxPersonalityFactoryImpl* newLinuxPersonalityFactoryImpl(void)
{
    return &GL_object;
}

static void deleteLinuxPersonalityFactoryImpl(struct tag_LinuxPersonalityFactoryImpl* object)
{
    return;
}


/*
 * IPersonalityFactory.
 */
static inline IPersonality* newPersonality(const void* self)
{
    LinuxPersonality*  object;


    object = newLinuxPersonality();
    return (object != NULL) ? &object->i_IPersonality : NULL;
}

/*
 * End of linux_Personality_factoryimpl.c
 */
