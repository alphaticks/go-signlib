# go-signlib
Go wrapper around different ECDSA signing libraries for faster signing

## Structure
lib/sign/src contains the Rust source of the library

## Usage
Use the makefile to build the library

**make library**    will compile the Rust library

Store the library file in desired location, and then use ecdsa.Load(path) before using the package
