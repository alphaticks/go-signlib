ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

clean:
	rm -rf ./lib/sign/target
	rm ./lib/sign.so

library:
	$(MAKE) -C lib/sign build

install:
	cp ./lib/sign/target/release/libsign.so /usr/lib

all: library
