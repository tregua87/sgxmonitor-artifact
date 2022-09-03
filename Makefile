SUBDIRS := src/client src/benchmark src/tracer src/monitor_batch src/custom_traced_batch src/contact_traced_batch src/custom_vanilla src/contac_vanilla
SUBDIRS_CLEAN := $(SUBDIRS)

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

# clean: $(SUBDIRS_CLEAN)
# $(SUBDIRS_CLEAN):
# 	$(MAKE) -C $@ clean

.PHONY: all $(SUBDIRS)
