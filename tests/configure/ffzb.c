#include <stdio.h>
#include <values.h>


int main(int argc, char *argv[])
{
    unsigned int result = 0;
    unsigned int value;
    int i;

    for (i = 1; i < argc; i++) {
        value = (unsigned int)strtoul(argv[i], NULL, 16);
        if (!value)
            return 1;
        result |= value;
    }

    for (i = 0; i < INTBITS; i++) {
        if (!(result&(1<<i))) {
            printf("0x%x\n", 1<<i);
            return 0;
        }
    }

    return 1;
}
