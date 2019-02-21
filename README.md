erl_ebpf
=====

Implementation of eBPF virtual machine to be used from Erlang.
eBPF program can be either llvm compiled object file or straight
binary containing eBPF machine code.

Supports calling external C functions. Can access Erlang binary
as "incoming packet source".

Build
-----

    $ make

Random comments
-----

This is very much work in progress and not correctly packaged.

1. Is MacOS specific, uses mac tools to package libraries
2. Requires https://github.com/taavi013/generic-ebpf compiled in specific
   location.
3. Has some local absolute path baked into files

But at least `make test` works in some situations:)

Todo
-----

1. Add possibility to modify "packet" given to eBPF program. Has to follow
   Erlang immutability.  How to actually implement it?
2. Implement various map_xx functions like Linux kernel provides.
