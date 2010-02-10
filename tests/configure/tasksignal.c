#include "autoconf.h"
#include "linux/sched.h"


int main()
{
    struct task_struct task;
    void *p = (void *)&task.real_timer;

    return 0;
}
