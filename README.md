## The SHA Package

![build](https://github.com/matthewhammer/motoko-sha/workflows/build/badge.svg)

### Overview

This package implements secure hash algorithms for the Motoko programming
language.

### Usage

Calculate the SHA256 checksum of the data.
```motoko
public func sha256(data : [Word8]) : [Word8]
```
