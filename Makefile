ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

clean:
	rm -rf ./lib/sign/target
	rm ./lib/sign/Cargo.lock ./lib/sign.so go-rust

library:
	$(MAKE) -C lib/sign build

install:
	cp ./lib/sign/target/release/libsign.a /usr/lib

all: library
