#include "linux/jiffies.h"
#include "linux/time.h"


int main()
{
    return msecs_to_jiffies(1000);
}
