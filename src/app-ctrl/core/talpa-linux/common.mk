
talpaLinuxSOURCES    =  src/app-ctrl/core/talpa-linux/talpa_linux_module.c \
                        src/platforms/linux/glue.c \
                        src/platforms/linux/vfs_mount.c \
                        src/components/services/linux_filesystem_impl/linux_systemroot.c \
                        src/components/services/linux_filesystem_impl/linux_filesystem_factoryimpl.c \
                        src/components/services/linux_filesystem_impl/linux_file.c \
                        src/components/services/linux_filesystem_impl/linux_fileinfo.c \
                        src/components/services/linux_filesystem_impl/linux_filesysteminfo.c \
                        src/components/services/linux_personality_impl/linux_personality_factoryimpl.c \
                        src/components/services/linux_personality_impl/linux_personality.c \
                        src/components/services/linux_processandthread_impl/linux_processandthread_factoryimpl.c \
                        src/components/services/linux_processandthread_impl/linux_threadinfo.c

talpaLinuxOBJS       =  $(talpaLinuxSOURCES:.c=.o)

talpaProcFSConfiguratorSOURCES = src/components/services/configurator_impl/procfs_configurator.c
talpaProcFSConfiguratorOBJS = $(talpaProcFSConfiguratorSOURCES:.c=.o)

talpaSecurityFSConfiguratorSOURCES = src/components/services/configurator_impl/securityfs_configurator.c
talpaSecurityFSConfiguratorOBJS = $(talpaSecurityFSConfiguratorSOURCES:.c=.o)

talpaDualFSConfiguratorSOURCES = src/components/services/configurator_impl/dualfs_configurator.c
talpaDualFSConfiguratorOBJS = $(talpaDualFSConfiguratorSOURCES:.c=.o)
