## The SHA Package

[![Build Status](https://travis-ci.org/enzoh/motoko-sha.svg?branch=master)](https://travis-ci.org/enzoh/motoko-sha?branch=master)

### Overview

This package implements secure hash algorithms for the Motoko programming
language.

### Usage

Calculate the SHA256 checksum of the data.
```motoko
public func sha256(data : [Word8]) : [Word8]
```
