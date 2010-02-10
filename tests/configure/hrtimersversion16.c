#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME "#lsmkeystest"
#endif

#include "autoconf.h"
#include <linux/hrtimer.h>

int main()
{
    ktime_t t;

    return hrtimer_forward(NULL, t);
}
