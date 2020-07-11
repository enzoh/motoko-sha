## The SHA Package

[![Build Status](https://github.com/enzoh/motoko-sha/workflows/build/badge.svg)](https://github.com/enzoh/motoko-sha/actions?query=workflow%3Abuild)

This package implements secure hash algorithms for the Motoko programming language.

### Prerequisites

- [DFINITY SDK](https://sdk.dfinity.org/docs/download.html) v0.5.11
- [Vessel](https://github.com/kritzcreek/vessel/releases/tag/v0.4.1) v0.4.1 (Optional)

### Usage

Calculate a SHA256 hash.
```motoko
public func sha256(data : [Word8]) : [Word8]
```
