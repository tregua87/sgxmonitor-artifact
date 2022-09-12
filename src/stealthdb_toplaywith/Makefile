UNTRUSTED_MK:= src/untrusted.mk
ENCLAVE_MK:= src/enclave.mk
APP_MK:=src/app.mk
MICROBENCHMARK_BATCH_MK:=src/microbenchmark_batch.mk
MICROBENCHMARK_LENGTH_MK:=src/microbenchmark_length.mk

.PHONY: all
all:
	$(MAKE) -C $(shell dirname $(UNTRUSTED_MK)) -f $(shell basename $(UNTRUSTED_MK)) $@
	$(MAKE) -C $(shell dirname $(ENCLAVE_MK)) -f $(shell basename $(ENCLAVE_MK)) $@
	$(MAKE) -C $(shell dirname $(APP_MK)) -f $(shell basename $(APP_MK)) $@
	$(MAKE) -C $(shell dirname $(MICROBENCHMARK_BATCH_MK)) -f $(shell basename $(MICROBENCHMARK_BATCH_MK)) $@
	$(MAKE) -C $(shell dirname $(MICROBENCHMARK_LENGTH_MK)) -f $(shell basename $(MICROBENCHMARK_LENGTH_MK)) $@

.PHONY: docker
docker:
	docker build -f docker/Dockerfile -t stealthdb:1.0 docker/
	docker run -it -d --rm --device=/dev/isgx --volume=/var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket -p 5432:5432 --name sdb stealthdb:1.0

.PHONY: install
install:
	$(MAKE) -C $(shell dirname $(UNTRUSTED_MK)) -f $(shell basename $(UNTRUSTED_MK)) $@
	$(MAKE) -C $(shell dirname $(ENCLAVE_MK)) -f $(shell basename $(ENCLAVE_MK)) $@

.PHONY: clean
clean:
	$(MAKE) -C $(shell dirname $(UNTRUSTED_MK)) -f $(shell basename $(UNTRUSTED_MK)) $@
	$(MAKE) -C $(shell dirname $(ENCLAVE_MK)) -f $(shell basename $(ENCLAVE_MK)) $@
	$(MAKE) -C $(shell dirname $(APP_MK)) -f $(shell basename $(APP_MK)) $@
	$(MAKE) -C $(shell dirname $(MICROBENCHMARK_MK)) -f $(shell basename $(MICROBENCHMARK_MK)) $@
	$(RM) -r build
