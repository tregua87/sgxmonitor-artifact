CC=$(LLVM_PATH)/build/bin/clang
CXX=$(LLVM_PATH)/build/bin/clang++

Dump.o: Dump.cpp
	@$(CC) -c $< -o $@
	@echo "CC   <=  $<"

.PHONY: clean

clean:
	@rm -f Dump.o
