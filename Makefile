ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

clean:
	rm -rf ./lib/starklib/target
	rm ./lib/starklib/Cargo.lock ./lib/starklib.so go-rust

library:
	$(MAKE) -C lib/starklib build

all: library
