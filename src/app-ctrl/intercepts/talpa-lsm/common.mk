
talpaLsmOBJS :=   src/app-ctrl/intercepts/talpa-lsm/talpa_lsm_module.o \
                  src/components/intercepts/lsm_impl/lsm_interceptor.o

talpaLsmSOURCES := $(talpaLsmOBJS:.o=.c)
