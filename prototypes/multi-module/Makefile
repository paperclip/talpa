KERNELDIR = /usr/src/linux

include $(KERNELDIR)/.config

CONFIG_FLAGS     = 
ifdef CONFIG_SMP
    CONFIG_FLAGS += -D__SMP__ -DSMP
endif

INCLUDES = -I$(KERNELDIR)/include
SYMS     = -D__KERNEL__ -DMODULE -DEXPORT_SYMTAB $(CONFIG_FLAGS)
CFLAGS   = $(SYMS) -O -Wall $(INCLUDES)

all: talpa-core-test.o talpa-test.o

clean:
	rm -f *.o *~ core
