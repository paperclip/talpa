#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#dotruncatetest"
#endif

#include <linux/autoconf.h>
#include <linux/fs.h>

int main()
{
    struct dentry *dentry = NULL;
    loff_t start = 0;
    unsigned int time_attrs = 0;

    return do_truncate(dentry, start, time_attrs);
}
