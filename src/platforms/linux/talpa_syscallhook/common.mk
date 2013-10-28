talpaSyscallHookSOURCES = src/platforms/linux/talpa_syscallhook/talpa_syscallhook.c \
				src/platforms/linux/glue.c

talpaSyscallHookOBJS    = $(talpaSyscallHookSOURCES:.c=.o)
