/*
 * TALPA test program
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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/sysctl.h>

#include "tlp-test.h"
#include "modules/tlp-test.h"

#define SIZE(x) sizeof(x)/sizeof(x[0])
#define NAMESZ 16

int path[] = { 7700, 2, 1, 1 };
const char *testval = "enable";
const char *testres = "enabled";

int main(int argc, char *argv[])
{
    char value[NAMESZ];
    size_t len = sizeof(value);

    if ( sysctl(path, SIZE(path), 0, 0, (void *)testval, strlen(testval)) )
    {
        fprintf(stderr, "Error setting to %s!\n", testres);
        return -errno;
    }

    if ( sysctl(path, SIZE(path), value, &len, 0, 0) )
    {
        fprintf(stderr, "Error reading value!\n");
        return -errno;
    }

    if ( strcmp(value, testres) )
    {
        fprintf(stderr, "Compare failed %s != %s\n", value, testres);
        return -1;
    }

    return 0;
}
