export class Reader {
  readonly view: DataView;
  readonly bytes: Uint8Array;
  pos = 0;

  constructor(bytes: Uint8Array, pos = 0) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.pos = pos;
  }

  get length() {
    return this.bytes.length;
  }

  seek(pos: number) {
    this.pos = pos;
    return this;
  }

  canRead(n: number, at = this.pos) {
    return at >= 0 && at + n <= this.bytes.length;
  }

  u8(at?: number) {
    const p = at ?? this.pos;
    if (at === undefined) this.pos += 1;
    return this.view.getUint8(p);
  }

  u16(at?: number) {
    const p = at ?? this.pos;
    if (at === undefined) this.pos += 2;
    return this.view.getUint16(p, true);
  }

  u32(at?: number) {
    const p = at ?? this.pos;
    if (at === undefined) this.pos += 4;
    return this.view.getUint32(p, true);
  }

  i32(at?: number) {
    const p = at ?? this.pos;
    if (at === undefined) this.pos += 4;
    return this.view.getInt32(p, true);
  }

  /** 64-bit unsigned read returned as a JS number (exact for real-world image values). */
  u64(at?: number) {
    const p = at ?? this.pos;
    if (at === undefined) this.pos += 8;
    const lo = this.view.getUint32(p, true);
    const hi = this.view.getUint32(p + 4, true);
    return hi * 0x100000000 + lo;
  }

  bytesAt(at: number, len: number) {
    return this.bytes.subarray(Math.max(0, at), Math.min(at + len, this.bytes.length));
  }

  /** Fixed-length ASCII field, NUL padded. */
  fixedAscii(at: number, len: number) {
    let s = '';
    for (let i = 0; i < len; i++) {
      const c = this.bytes[at + i];
      if (c === undefined || c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }

  /** NUL-terminated ASCII string. */
  cstr(at: number, max = 4096) {
    let s = '';
    for (let i = 0; i < max; i++) {
      const c = this.bytes[at + i];
      if (c === undefined || c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }

  /** NUL-terminated UTF-16LE string. */
  wstr(at: number, chars: number) {
    let s = '';
    for (let i = 0; i < chars; i++) {
      if (!this.canRead(2, at + i * 2)) break;
      const c = this.view.getUint16(at + i * 2, true);
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }
}

export const hex = (n: number, pad = 8) =>
  '0x' + (n >>> 0).toString(16).toUpperCase().padStart(pad, '0');

export const hexBig = (n: number, pad = 8) => {
  if (n <= 0xffffffff) return hex(n, pad);
  return '0x' + Math.round(n).toString(16).toUpperCase().padStart(pad, '0');
};

export const formatSize = (n: number) => {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10240 ? 2 : 1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
};
