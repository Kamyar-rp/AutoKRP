/* هش افزایشی (تکه‌تکه) برای فایل‌های بزرگ، بدون کتابخانه و بدون ارسال فایل به جایی:
   MD5، SHA-1، SHA-256، SHA-512 و CRC32. هر کدام: const h = new X(); h.update(Uint8Array); h.hex()  */
"use strict";
const OffHash = (() => {
  const hex32 = (n) => (n >>> 0).toString(16).padStart(8, "0");

  /* پایه‌ی مشترک: بافر بلوک ۶۴ یا ۱۲۸ بایتی */
  class Block {
    constructor(size) { this.bs = size; this.buf = new Uint8Array(size); this.n = 0; this.len = 0; }
    update(d) {
      let i = 0; const L = d.length; this.len += L;
      if (this.n) {
        const k = Math.min(this.bs - this.n, L); this.buf.set(d.subarray(0, k), this.n); this.n += k; i = k;
        if (this.n === this.bs) { this.block(this.buf, 0); this.n = 0; }
      }
      for (; i + this.bs <= L; i += this.bs) this.block(d, i);
      if (i < L) { this.buf.set(d.subarray(i), 0); this.n = L - i; }
      return this;
    }
    pad(bigEndian, lenBytes) {
      const bits = this.len * 8, tail = new Uint8Array(this.bs * 2);
      tail.set(this.buf.subarray(0, this.n)); tail[this.n] = 0x80;
      const total = this.n + 1 + lenBytes <= this.bs ? this.bs : this.bs * 2;
      const hi = Math.floor(bits / 4294967296), lo = bits >>> 0;
      if (bigEndian) { new DataView(tail.buffer).setUint32(total - 8, hi); new DataView(tail.buffer).setUint32(total - 4, lo); }
      else { new DataView(tail.buffer).setUint32(total - 8, lo, true); new DataView(tail.buffer).setUint32(total - 4, hi, true); }
      for (let o = 0; o < total; o += this.bs) this.block(tail, o);
    }
  }

  const MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0);
  class MD5 extends Block {
    constructor() { super(64); this.h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]; this.w = new Int32Array(16); }
    block(d, o) {
      const w = this.w;
      for (let i = 0; i < 16; i++) w[i] = d[o + i * 4] | (d[o + i * 4 + 1] << 8) | (d[o + i * 4 + 2] << 16) | (d[o + i * 4 + 3] << 24);
      let [a, b, c, e] = this.h;
      for (let i = 0; i < 64; i++) {
        let f, g;
        if (i < 16) { f = (b & c) | (~b & e); g = i; }
        else if (i < 32) { f = (e & b) | (~e & c); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ e; g = (3 * i + 5) & 15; }
        else { f = c ^ (b | ~e); g = (7 * i) & 15; }
        const t = (a + f + MD5_K[i] + w[g]) | 0, s = MD5_S[i];
        a = e; e = c; c = b; b = (b + ((t << s) | (t >>> (32 - s)))) | 0;
      }
      this.h[0] = (this.h[0] + a) | 0; this.h[1] = (this.h[1] + b) | 0; this.h[2] = (this.h[2] + c) | 0; this.h[3] = (this.h[3] + e) | 0;
    }
    hex() { this.pad(false, 8); return this.h.map((x) => hex32(((x & 0xff) << 24) | ((x >>> 8 & 0xff) << 16) | ((x >>> 16 & 0xff) << 8) | (x >>> 24))).join(""); }
  }

  class SHA1 extends Block {
    constructor() { super(64); this.h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]; this.w = new Int32Array(80); }
    block(d, o) {
      const w = this.w;
      for (let i = 0; i < 16; i++) w[i] = (d[o + i * 4] << 24) | (d[o + i * 4 + 1] << 16) | (d[o + i * 4 + 2] << 8) | d[o + i * 4 + 3];
      for (let i = 16; i < 80; i++) { const x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]; w[i] = (x << 1) | (x >>> 31); }
      let [a, b, c, e, f] = this.h;
      for (let i = 0; i < 80; i++) {
        let k, fn;
        if (i < 20) { fn = (b & c) | (~b & e); k = 0x5a827999; }
        else if (i < 40) { fn = b ^ c ^ e; k = 0x6ed9eba1; }
        else if (i < 60) { fn = (b & c) | (b & e) | (c & e); k = 0x8f1bbcdc; }
        else { fn = b ^ c ^ e; k = 0xca62c1d6; }
        const t = (((a << 5) | (a >>> 27)) + fn + f + k + w[i]) | 0;
        f = e; e = c; c = (b << 30) | (b >>> 2); b = a; a = t;
      }
      const h = this.h; h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + e) | 0; h[4] = (h[4] + f) | 0;
    }
    hex() { this.pad(true, 8); return this.h.map(hex32).join(""); }
  }

  const K256 = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  class SHA256 extends Block {
    constructor() { super(64); this.h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]; this.w = new Int32Array(64); }
    block(d, o) {
      const w = this.w;
      for (let i = 0; i < 16; i++) w[i] = (d[o + i * 4] << 24) | (d[o + i * 4 + 1] << 16) | (d[o + i * 4 + 2] << 8) | d[o + i * 4 + 3];
      for (let i = 16; i < 64; i++) {
        const x = w[i - 15], y = w[i - 2];
        const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let [a, b, c, e, f, g, h, k] = this.h;
      for (let i = 0; i < 64; i++) {
        const S1 = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7));
        const t1 = (k + S1 + ((f & g) ^ (~f & h)) + K256[i] + w[i]) | 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const t2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        k = h; h = g; g = f; f = (e + t1) | 0; e = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      const H = this.h; [a, b, c, e, f, g, h, k].forEach((v, i) => (H[i] = (H[i] + v) | 0));
    }
    hex() { this.pad(true, 8); return this.h.map(hex32).join(""); }
  }

  /* SHA-512 با جفت‌های ۳۲ بیتی (hi, lo) */
  const K512 = ["428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc", "3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b",
    "ab1c5ed5da6d8118", "d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2", "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235",
    "c19bf174cf692694", "e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65", "2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4",
    "76f988da831153b5", "983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4", "c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f",
    "142929670a0e6e70", "27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df", "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6",
    "92722c851482353b", "a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30", "d192e819d6ef5218", "d69906245565a910", "f40e35855771202a",
    "106aa07032bbd1b8", "19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8", "391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373",
    "682e6ff3d6b2b8a3", "748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec", "90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915",
    "c67178f2e372532b", "ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178", "06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae",
    "1b710b35131c471b", "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c", "4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec",
    "6c44198c4a475817"];
  const K5 = new Int32Array(160); K512.forEach((s, i) => { K5[2 * i] = parseInt(s.slice(0, 8), 16) | 0; K5[2 * i + 1] = parseInt(s.slice(8), 16) | 0; });
  const H512 = ["6a09e667f3bcc908", "bb67ae8584caa73b", "3c6ef372fe94f82b", "a54ff53a5f1d36f1", "510e527fade682d1", "9b05688c2b3e6c1f", "1f83d9abfb41bd6b", "5be0cd19137e2179"];
  class SHA512 extends Block {
    constructor() {
      super(128); this.h = new Int32Array(16); H512.forEach((s, i) => { this.h[2 * i] = parseInt(s.slice(0, 8), 16) | 0; this.h[2 * i + 1] = parseInt(s.slice(8), 16) | 0; });
      this.w = new Int32Array(160);
    }
    block(d, o) {
      const W = this.w;
      for (let i = 0; i < 32; i++) W[i] = (d[o + i * 4] << 24) | (d[o + i * 4 + 1] << 16) | (d[o + i * 4 + 2] << 8) | d[o + i * 4 + 3];
      for (let i = 16; i < 80; i++) {
        // σ0 = rotr1 ^ rotr8 ^ shr7 ؛ σ1 = rotr19 ^ rotr61 ^ shr6
        let xh = W[(i - 15) * 2], xl = W[(i - 15) * 2 + 1];
        const s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
        const s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));
        xh = W[(i - 2) * 2]; xl = W[(i - 2) * 2 + 1];
        const s1h = ((xh >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (xh << 3)) ^ (xh >>> 6);
        const s1l = ((xl >>> 19) | (xh << 13)) ^ ((xh >>> 29) | (xl << 3)) ^ ((xl >>> 6) | (xh << 26));
        let lo = (W[(i - 16) * 2 + 1] >>> 0) + (s0l >>> 0) + (W[(i - 7) * 2 + 1] >>> 0) + (s1l >>> 0);
        let hi = W[(i - 16) * 2] + s0h + W[(i - 7) * 2] + s1h + Math.floor(lo / 4294967296);
        W[i * 2] = hi | 0; W[i * 2 + 1] = lo | 0;
      }
      const H = this.h;
      let ah = H[0], al = H[1], bh = H[2], bl = H[3], ch = H[4], cl = H[5], dh = H[6], dl = H[7];
      let eh = H[8], el = H[9], fh = H[10], fl = H[11], gh = H[12], gl = H[13], hh = H[14], hl = H[15];
      for (let i = 0; i < 80; i++) {
        // Σ1(e) = rotr14 ^ rotr18 ^ rotr41
        const S1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23));
        const S1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23));
        const chh = (eh & fh) ^ (~eh & gh), chl = (el & fl) ^ (~el & gl);
        let t1l = (hl >>> 0) + (S1l >>> 0) + (chl >>> 0) + (K5[i * 2 + 1] >>> 0) + (W[i * 2 + 1] >>> 0);
        let t1h = hh + S1h + chh + K5[i * 2] + W[i * 2] + Math.floor(t1l / 4294967296);
        t1l |= 0; t1h |= 0;
        // Σ0(a) = rotr28 ^ rotr34 ^ rotr39
        const S0h = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25));
        const S0l = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25));
        const mjh = (ah & bh) ^ (ah & ch) ^ (bh & ch), mjl = (al & bl) ^ (al & cl) ^ (bl & cl);
        let t2l = (S0l >>> 0) + (mjl >>> 0), t2h = S0h + mjh + Math.floor(t2l / 4294967296);
        hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;
        let nl = (dl >>> 0) + (t1l >>> 0); eh = (dh + t1h + Math.floor(nl / 4294967296)) | 0; el = nl | 0;
        dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al;
        nl = (t1l >>> 0) + (t2l >>> 0); ah = (t1h + t2h + Math.floor(nl / 4294967296)) | 0; al = nl | 0;
      }
      const add = (i, h, l) => { const s = (H[i + 1] >>> 0) + (l >>> 0); H[i] = (H[i] + h + Math.floor(s / 4294967296)) | 0; H[i + 1] = s | 0; };
      add(0, ah, al); add(2, bh, bl); add(4, ch, cl); add(6, dh, dl); add(8, eh, el); add(10, fh, fl); add(12, gh, gl); add(14, hh, hl);
    }
    hex() { this.pad(true, 16); return Array.from(this.h, hex32).join(""); }
  }

  const CRC_T = new Int32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; CRC_T[n] = c; }
  class CRC32 {
    constructor() { this.c = -1; }
    update(d) { let c = this.c; for (let i = 0; i < d.length; i++) c = CRC_T[(c ^ d[i]) & 0xff] ^ (c >>> 8); this.c = c; return this; }
    hex() { return hex32(~this.c); }
  }

  const ALGOS = [["MD5", MD5, 32], ["SHA-1", SHA1, 40], ["SHA-256", SHA256, 64], ["SHA-512", SHA512, 128], ["CRC32", CRC32, 8]];
  return { MD5, SHA1, SHA256, SHA512, CRC32, ALGOS };
})();
if (typeof module !== "undefined") module.exports = OffHash;
