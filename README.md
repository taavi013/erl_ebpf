erl_ebpf
=====

An OTP application

Build
-----

    $ rebar3 compile

Random comments
-----

This is very much work in progress and not correctly packaged.

1. Is MacOS specific, uses mac tools to package libraries
2. Requires https://github.com/taavi013/generic-ebpf compiled in specific
   location.
3. Has some local absolute path baked into files

But at least `make test` works in some situations:)
