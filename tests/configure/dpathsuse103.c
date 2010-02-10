#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#dpathtest"
#endif

#include "autoconf.h"
#include <linux/fs.h>

int main()
{
    struct dentry *dentry = NULL;
    struct vfsmount *vfsmnt = NULL;
    char *buffer = NULL;
    unsigned int buflen = 0;
    unsigned int fail_deleted = 0;
    char *path = __d_path(dentry, vfsmnt, dentry, vfsmnt, buffer, buflen, fail_deleted);

    return 0;
}
