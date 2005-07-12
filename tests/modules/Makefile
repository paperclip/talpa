
EXTRA_CFLAGS += -I$(src)/../../src -I$(src)/../../src/ifaces -I$(src)/../../include -DDEBUG -g @inodeallocsem@ @tasknewtty@

obj-m :=    tlp-personality.o \
            tlp-fileinfo.o \
            tlp-filesysteminfo.o \
            tlp-syslog.o \
            tlp-procfs.o \
            tlp-stdinterceptor.o \
            tlp-inclusion.o \
            tlp-opexcl.o \
            tlp-denysyslog.o \
            tlp-threadinfo.o \
            tlp-exclusion.o \
            tlp-ddvc.o \
            tlp-cacheobj.o \
            tlp-cache.o \
            tlp-degrmode.o \
            tlp-file.o

include $(src)/common.mk

tlp-personality-objs := $(tlpPersonalityOBJS)
tlp-fileinfo-objs := $(tlpFileInfoOBJS)
tlp-filesysteminfo-objs := $(tlpFilesystemInfoOBJS)
tlp-syslog-objs := $(tlpSyslogOBJS)
tlp-procfs-objs := $(tlpProcfsOBJS)
tlp-stdinterceptor-objs := $(tlpStdInterceptorOBJS)
tlp-inclusion-objs := $(tlpInclusionOBJS)
tlp-opexcl-objs := $(tlpOpExclOBJS)
tlp-denysyslog-objs := $(tlpDenySyslogOBJS)
tlp-threadinfo-objs := $(tlpThreadInfoOBJS)
tlp-exclusion-objs := $(tlpExclusionOBJS)
tlp-ddvc-objs := $(tlpDDVCOBJS)
tlp-cacheobj-objs := $(tlpCacheObjOBJS)
tlp-cache-objs := $(tlpCacheOBJS)
tlp-degrmode-objs := $(tlpDegrModeOBJS)
tlp-file-objs := $(tlpFileOBJS)

# Hidden by makefile, which is run in preference.  If makefile doesn't exist,
# then we shall cry foul.
all:
	@echo "Please run 'configure' before building."
	@exit 1
