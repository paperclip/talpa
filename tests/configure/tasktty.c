#include "autoconf.h"
#include "linux/sched.h"


int main()
{
  struct task_struct task;

  task.tty = NULL;

  return 0;
}
