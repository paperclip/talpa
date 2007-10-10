#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#dpathtest"
#endif

#include <linux/autoconf.h>
#include <linux/fs.h>

int main()
{
    struct dentry *dentry = NULL;
    struct vfsmount *vfsmnt = NULL;
    char *buffer = NULL;
    unsigned int buflen = 0;
    char *path = __d_path(dentry, vfsmnt, dentry, vfsmnt, buffer, buflen);

    return 0;
}
