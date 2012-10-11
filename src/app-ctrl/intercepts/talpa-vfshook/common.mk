
talpaVFSHookSOURCES =  src/app-ctrl/intercepts/talpa-vfshook/talpa_vfshook_module.c \
                       src/components/intercepts/vfshook_impl/vfshook_interceptor.c \
                       src/platforms/linux/glue.c \
                       src/platforms/linux/vfs_mount.c

talpaVFSHookOBJS    =  $(talpaVFSHookSOURCES:.c=.o)
