# findcrypt

[![Build Status](https://travis-ci.org/andrew-d/findcrypt.svg?branch=master)](https://travis-ci.org/andrew-d/findcrypt)

`findcrypt` is a tool that can scan a file to look for signatures of common
crypto algorithms (e.g. SHA256, AES/Rijndael, etc.).  It supports searching for
signatures in both big- and little-endian files.

The search algorithm used is also fast enough to search a large amount of data
in a short amount of time - some unscientific benchmarks show that the tool can
search about 1.1 GiB of data in about 20 seconds, at a speed of about 60 MiB/s:

## Simple Benchmark

Using a Ubuntu ISO I had lying around:

```
$ ls -alh ubuntu-14.10-desktop-amd64.iso
-rw-r-----@ 1 andrew  staff   1.1G Nov  4  2014 ubuntu-14.10-desktop-amd64.iso
$ time ./target/release/findcrypt ubuntu-14.10-desktop-amd64.iso
<snipped>
./target/release/findcrypt ubuntu-14.10-desktop-amd64.iso  10.16s user 1.55s system 65% cpu 17.758 total
```

This works out to a search speed of 62.45MiB/sec.

## License

GPLv3
