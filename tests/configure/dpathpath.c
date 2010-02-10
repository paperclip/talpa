#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#dpathtest"
#endif

#include "autoconf.h"
#include <linux/fs.h>

int main()
{
    struct path *pathst = NULL;
    char *buffer = NULL;
    unsigned int buflen = 0;
    char *path = __d_path(pathst, pathst, buffer, buflen);

    return 0;
}
