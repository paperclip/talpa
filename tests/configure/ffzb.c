#include <stdio.h>
#include <values.h>


int main(int argc, char *argv[])
{
    unsigned int result = PF_TALPA_ALL;
    int i;


    if (!result)
        return 2;

    for (i = 0; i < INTBITS; i++) {
        if (!(result&(1<<i))) {
            printf("0x%x\n", 1<<i);
            return 0;
        }
    }

    return 1;
}
