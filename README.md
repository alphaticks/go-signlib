# go-starklib
Go wrapper around starknet-rs library for fast signing on STARK curve

## Structure
lib/starklib/src contains the Rust source of the library

## Usage
Use the makefile to build the library

**make library**    will compile the Rust library

Store the library file in desired location, and then use ecdsa.Load(path) before using the package
