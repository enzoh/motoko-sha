/**
 * Module      : SHA256.mo
 * Description : Cryptographic hash function.
 * Copyright   : 2020 DFINITY Stiftung
 * License     : Apache 2.0 with LLVM Exception
 * Maintainer  : Enzo Haussecker <enzo@dfinity.org>
 * Stability   : Stable
 */

import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Iter "mo:base/Iter";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Blob "mo:base/Blob";

module {

    private let K : [Nat32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    private let S : [Nat32] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Calculate a SHA256 hash.
    public func sha256(data : Blob) : Blob {
        let digest = Digest();
        let _ = digest.write(data.vals());
        return digest.sum();
    };

    // Calculate a SHA256 hash.
    public func sha256_fromIter(iter : Iter.Iter<Nat8>) : Blob {
        let digest = Digest();
        let _ = digest.write(iter);
        return digest.sum();
    };

    // A fixed length buffer of type T that can be filled from an iterator
    // until the buffer is full or the iterator is exhausted.
    // val is an arbitrary value of type T, used only to initialize an array
    public class BlockBuffer<T>(size : Nat, val : T) {
        private let buffer : [var T] = Array.init<T>(size, val);
        private var pos : Nat = 0;

        public func reset() {
            pos := 0;
        };

        public func fill(i : Iter.Iter<T>) : Nat {
            let start = pos;
            label emptied while (pos < size) {
                switch (i.next()) {
                    case (?v) {
                        buffer[pos] := v;
                        pos += 1;
                        };
                    case (null) {
                        break emptied
                        };
                };
            };
            pos - start
        };

        public func isFull() : Bool {
            pos == size;
        };

        public func toArray() : [T] {
            Array.tabulate<T>(pos, func(i) { buffer[i] });    
        };
    };

  public class Digest() {
    private var len : Nat = 0;
    private let state : [var Nat32] = Array.thaw<Nat32>(S);
    private let buffer : BlockBuffer<Nat8> = BlockBuffer(64, 0:Nat8);

    public func reset() {
        len := 0;
        buffer.reset();
        for (i in Iter.range(0, 7)) {
           state[i] := S[i];
        };
    };

    public func write(iter : Iter.Iter<Nat8>) : Nat {
        // will return the number of bytes read from iter
        var bytes_read : Nat = 0;
        label reading loop {
            // fill the buffer
            bytes_read += buffer.fill(iter);
            if (buffer.isFull()) {
                // buffer is full, going to hash one block and try again
                block(buffer.toArray());
                buffer.reset();
                continue reading
            } else {
                // iter is exhausted
                break reading
            }
        };
        len += bytes_read;
        bytes_read
    };

    // hash one block
    private func block(data : [Nat8]) {
        assert data.size() == 64;
        var w = Array.init<Nat32>(64, 0);
        for (i in Iter.range(0, 15)) {
            w[i] :=
                Nat32.fromIntWrap(Nat8.toNat(data[4*i + 0])) << 24 |
                Nat32.fromIntWrap(Nat8.toNat(data[4*i + 1])) << 16 |
                Nat32.fromIntWrap(Nat8.toNat(data[4*i + 2])) << 08 |
                Nat32.fromIntWrap(Nat8.toNat(data[4*i + 3])) << 00;
        };
        let rot = Nat32.bitrotRight;
        for (i in Iter.range(16, 63)) {
          let (v0, v1) = (w[i - 15], w[i - 02]);
          let s0 = rot(v0, 07) ^ rot(v0, 18) ^ (v0 >> 03);
          let s1 = rot(v1, 17) ^ rot(v1, 19) ^ (v1 >> 10);
          w[i] := w[i - 16] +% s0 +% w[i - 07] +% s1;
        };
        var a = state[0];
        var b = state[1];
        var c = state[2];
        var d = state[3];
        var e = state[4];
        var f = state[5];
        var g = state[6];
        var h = state[7];
        for (i in Iter.range(0, 63)) {
          let ch = (e & f) ^ (^ e & g);
          let ma = (a & b) ^ (a & c) ^ (b & c);
          let sigma0 = rot(a, 02) ^ rot(a, 13) ^ rot(a, 22);
          let sigma1 = rot(e, 06) ^ rot(e, 11) ^ rot(e, 25);
          let t = h +% K[i] +% w[i] +% ch +% sigma1;
          h := g;
          g := f;
          f := e;
          e := d +% t;
          d := c;
          c := b;
          b := a;
          a := t +% ma +% sigma0;
        };
        state[0] +%= a;
        state[1] +%= b;
        state[2] +%= c;
        state[3] +%= d;
        state[4] +%= e;
        state[5] +%= f;
        state[6] +%= g;
        state[7] +%= h;
    };    

    private func bigendian_nat64(n: Nat64) : [Nat8] {
        let mod8 = func(n : Nat64) : Nat8 {
            Nat8.fromIntWrap(Nat64.toNat(n))
        };
        let ith_byte = func(i : Nat) : Nat8 {
            let shift = 8 * (7 - i);
            mod8(n >> Nat64.fromNat(shift))
        };
        Array.tabulate<Nat8>(8, ith_byte)
    };

   private func bigendian_nat32(n: Nat32) : [Nat8] {
        let mod8 = func(n : Nat32) : Nat8 {
            Nat8.fromIntWrap(Nat32.toNat(n))
        };
        let ith_byte = func(i : Nat) : Nat8 {
            let shift = 8 * (3 - i);
            mod8(n >> Nat32.fromNat(shift))
        };
        Array.tabulate<Nat8>(4, ith_byte)
    };

    public func sum() : Blob {
      // save the length before writing more bytes
      var n = Nat64.fromNat(len);

      // write padding
      let t = len % 64;
      let m = if (56 > t) (56 - t) else (120 - t);
      let padding = Array.tabulate<Nat8>(m, func(i) { if (i==0) 0x80 else 0 });
      let _ = write(padding.vals());

      // write length
      let _ = write(bigendian_nat64(n*8).vals());

      // retrieve sum
      let hash = Buffer.Buffer<Nat8>(32);
      for (i in Iter.range(0, 7)) {
            let w = bigendian_nat32(state[i]);
            hash.add(w[0]);
            hash.add(w[1]);
            hash.add(w[2]);
            hash.add(w[3]);
      };
      return Blob.fromArray(hash.toArray());
    };
  }; // class Digest
};
