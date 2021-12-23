/**
 * Module      : SHA512.mo
 * Description : Cryptographic hash function.
 * Copyright   : 2020 DFINITY Stiftung
 * License     : Apache 2.0 with LLVM Exception
 * Maintainer  : Enzo Haussecker <enzo@dfinity.org>
 * Stability   : Stable
 */

import Array "mo:base/Array";
import Iter "mo:base/Iter";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";

module {
  private let ROUNDS = 80;
  private let WORD_SIZE = 8;
  private let BLOCK_SIZE = 128;
  private let LENGTH_SIZE = 16;
  // 2**128 - 1
  private let MAX_LENGTH = 0xffffffffffffffffffffffffffffffff;

  private let K : [Nat64] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817
  ];

  private let S : [Nat64] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
  ];

  // Calculate a SHA512 hash.
  public func sha512(data : [Nat8]) : [Nat8] {
    let digest = Digest();
    digest.write(data);
    return digest.sum();
  };

  public class Digest() {

    private let s = Array.thaw<Nat64>(S);

    private let x = Array.init<Nat8>(BLOCK_SIZE, 0);

    private var nx = 0;

    private var len = 0;

    public func reset() {
      for (i in Iter.range(0, 7)) {
        s[i] := S[i];
      };
      nx := 0;
      len := 0;
    };

    public func write(data : [Nat8]) {
      var p = data;
      len += p.size();
      len %= MAX_LENGTH + 1;
      if (nx > 0) {
        let n = Nat.min(p.size(), BLOCK_SIZE - nx);
        for (i in Iter.range(0, n - 1)) {
          x[nx + i] := p[i];
        };
        nx += n;
        if (nx == BLOCK_SIZE) {
          let buf = Array.freeze<Nat8>(x);
          block(buf);
          nx := 0;
        };
        p := Array.tabulate<Nat8>(p.size() - n, func (i) {
          return p[n + i];
        });
      };
      while (p.size() >= BLOCK_SIZE) {
        let buf = Array.tabulate<Nat8>(BLOCK_SIZE, func (i) {
          return p[i];
        });
        block(buf);
        p := Array.tabulate<Nat8>(p.size() - BLOCK_SIZE, func (i) {
          return p[BLOCK_SIZE + i];
        });
      };
      if (p.size() > 0) {
        for (i in Iter.range(0, p.size() - 1)) {
          x[i] := p[i];
        };
        nx := p.size();
      };
    };

    public func sum() : [Nat8] {
      var m = 0;
      var n = len;
      var t = n % BLOCK_SIZE;
      var buf : [var Nat8] = [var];

      if (BLOCK_SIZE > t + LENGTH_SIZE) {
        m := BLOCK_SIZE - LENGTH_SIZE - t;
      } else {
        m := BLOCK_SIZE * 2 - LENGTH_SIZE - t;
      };
      n := n * 8; // << 3
      buf := Array.init<Nat8>(m, 0);
      if (m > 0) {
        buf[0] := 0x80;
      };
      write(Array.freeze<Nat8>(buf));
      buf := Array.init<Nat8>(LENGTH_SIZE, 0);
      for (i in Iter.range(0, LENGTH_SIZE - 1)) {
        let j: Nat = BLOCK_SIZE - 8 - 8 * i;
        buf[i] := Nat8.fromIntWrap(n / (2**j));
      };
      write(Array.freeze<Nat8>(buf));
      let hash = Array.init<Nat8>(64, 0);
      for (i in Iter.range(0, 7)) {
        for (j in Iter.range(0, WORD_SIZE - 1)) {
          let k : Nat64 = Nat64.fromIntWrap(WORD_SIZE * 8)
            - 8 -% 8 *% Nat64.fromIntWrap(j);
          hash[8 * i + j] := Nat8.fromIntWrap(Nat64.toNat(s[i] >> k));
        };
      };
      return Array.freeze<Nat8>(hash);
    };

    private func block(data : [Nat8]) {
      var p = data;
      var w = Array.init<Nat64>(ROUNDS, 0);
      while (p.size() >= BLOCK_SIZE) {
        var j = 0;
        for (i in Iter.range(0, 15)) {
          j := i * WORD_SIZE;
          w[i] :=
            Nat64.fromIntWrap(Nat8.toNat(p[j + 0])) << 56 |
            Nat64.fromIntWrap(Nat8.toNat(p[j + 1])) << 48 |
            Nat64.fromIntWrap(Nat8.toNat(p[j + 2])) << 40 |
            Nat64.fromIntWrap(Nat8.toNat(p[j + 3])) << 32 |
            Nat64.fromIntWrap(Nat8.toNat(p[j + 4])) << 24 |
            Nat64.fromIntWrap(Nat8.toNat(p[j + 5])) << 16 |
            Nat64.fromIntWrap(Nat8.toNat(p[j + 6])) << 08 |
            Nat64.fromIntWrap(Nat8.toNat(p[j + 7])) << 00;
        };
        var v1 : Nat64 = 0;
        var v2 : Nat64 = 0;
        var t1 : Nat64 = 0;
        var t2 : Nat64 = 0;
        var s0 : Nat64 = 0;
        var s1 : Nat64 = 0;
        var maj : Nat64 = 0;
        var ch : Nat64 = 0;
        for (i in Iter.range(16, ROUNDS - 1)) {
          v1 := w[i - 02];
          v2 := w[i - 15];
          t1 := rot(v1, 19) ^ rot(v1, 61) ^ (v1 >> 06);
          t2 := rot(v2, 01) ^ rot(v2, 08) ^ (v2 >> 07);
          w[i] :=
              t1 +% w[i - 07] +%
              t2 +% w[i - 16];
        };
        var a = s[0];
        var b = s[1];
        var c = s[2];
        var d = s[3];
        var e = s[4];
        var f = s[5];
        var g = s[6];
        var h = s[7];
        for (i in Iter.range(0, ROUNDS - 1)) {
          t1 := rot(e, 14) ^ rot(e, 18) ^ rot(e, 41);
          t1 +%= (e & f) ^ (^ e & g) +% h +% K[i] +% w[i];
          t2 := rot(a, 28) ^ rot(a, 34) ^ rot(a, 39);
          t2 +%= (a & b) ^ (a & c) ^ (b & c);

          h := g;
          g := f;
          f := e;
          e := d +% t1;
          d := c;
          c := b;
          b := a;
          a := t1 +% t2;
        };
        s[0] +%= a;
        s[1] +%= b;
        s[2] +%= c;
        s[3] +%= d;
        s[4] +%= e;
        s[5] +%= f;
        s[6] +%= g;
        s[7] +%= h;
        p := Array.tabulate<Nat8>(p.size() - BLOCK_SIZE, func (i) {
          return p[i + BLOCK_SIZE];
        });
      };
    };
  };
  private let rot : (Nat64, Nat64) -> Nat64 = Nat64.bitrotRight;
};
