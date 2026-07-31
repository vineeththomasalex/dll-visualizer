import { Reader } from '../pe/reader';

export interface Symbol {
  name: string;
  pretty: string;
  rva: number;
  section: number;
  offset: number;
  kind: 'public' | 'function' | 'data' | 'thunk' | 'map';
  size?: number;
  moduleName?: string;
  source: 'pdb' | 'map';
}

export interface PdbInfo {
  guid: string;
  age: number;
  signature: number;
  blockSize: number;
  streamCount: number;
  machine?: number;
  modules: { name: string; objectFile: string; symbolBytes: number }[];
  symbols: Symbol[];
}

const MSF_MAGIC_7 = 'Microsoft C/C++ MSF 7.00\r\n\u001aDS';

class MsfFile {
  reader: Reader;
  blockSize: number;
  streams: Uint8Array[] = [];

  constructor(bytes: Uint8Array) {
    this.reader = new Reader(bytes);
    const magic = this.reader.fixedAscii(0, 30);
    if (!magic.startsWith('Microsoft C/C++ MSF 7.00')) {
      if (magic.startsWith('Microsoft C/C++ program database 2.00')) {
        throw new Error('This is a PDB 2.00 file (VC6 era). Only the modern PDB 7.00 container is supported.');
      }
      throw new Error('Not a PDB file — the MSF signature is missing.');
    }
    void MSF_MAGIC_7;
    this.blockSize = this.reader.u32(32);
    const numBlocks = this.reader.u32(40);
    const numDirBytes = this.reader.u32(44);
    const blockMapAddr = this.reader.u32(52);
    if (!this.blockSize || bytes.length < this.blockSize) throw new Error('Corrupt PDB superblock.');

    const dirBlockCount = Math.ceil(numDirBytes / this.blockSize);
    const dirBlockIds: number[] = [];
    for (let i = 0; i < dirBlockCount; i++) {
      dirBlockIds.push(this.reader.u32(blockMapAddr * this.blockSize + i * 4));
    }
    const dir = this.readBlocks(dirBlockIds, numDirBytes);
    const dr = new Reader(dir);
    const numStreams = dr.u32(0);
    if (numStreams > 100000) throw new Error('Implausible stream count — the PDB may be corrupt.');
    const sizes: number[] = [];
    for (let i = 0; i < numStreams; i++) sizes.push(dr.u32(4 + i * 4));
    let p = 4 + numStreams * 4;
    for (let i = 0; i < numStreams; i++) {
      const size = sizes[i] === 0xffffffff ? 0 : sizes[i];
      const count = Math.ceil(size / this.blockSize);
      const ids: number[] = [];
      for (let b = 0; b < count; b++) {
        ids.push(dr.u32(p));
        p += 4;
      }
      this.streams.push(this.readBlocks(ids, size, numBlocks));
    }
  }

  private readBlocks(ids: number[], size: number, maxBlocks?: number): Uint8Array {
    const out = new Uint8Array(size);
    let written = 0;
    for (const id of ids) {
      if (maxBlocks && id >= maxBlocks) break;
      const start = id * this.blockSize;
      const chunk = this.reader.bytesAt(start, Math.min(this.blockSize, size - written));
      out.set(chunk, written);
      written += chunk.length;
      if (written >= size) break;
    }
    return out;
  }
}

/**
 * Lightly "undecorates" MSVC symbol names so the UI stays readable without
 * shipping a full demangler.
 */
export function prettifySymbol(name: string): string {
  if (!name) return name;
  if (name.startsWith('?')) {
    const body = name.slice(1);
    const at = body.indexOf('@@');
    if (at > 0) {
      const qualified = body.slice(0, at);
      const parts = qualified.split('@').filter(Boolean);
      if (parts.length > 1) {
        const fn = parts[0];
        const scope = parts.slice(1).reverse().join('::');
        return `${scope}::${fn}`;
      }
      return qualified;
    }
    return body;
  }
  // stdcall / fastcall decorations: _Foo@12, @Foo@12
  const m = /^[_@]([A-Za-z_$][\w$]*)@\d+$/.exec(name);
  if (m) return m[1];
  if (/^_[A-Za-z_$]/.test(name)) return name.slice(1);
  return name;
}

function guidFrom(r: Reader, at: number) {
  const d1 = r.u32(at).toString(16).padStart(8, '0');
  const d2 = r.u16(at + 4).toString(16).padStart(4, '0');
  const d3 = r.u16(at + 6).toString(16).padStart(4, '0');
  let rest = '';
  for (let i = 0; i < 8; i++) rest += r.u8(at + 8 + i).toString(16).padStart(2, '0');
  return `${d1}-${d2}-${d3}-${rest.slice(0, 4)}-${rest.slice(4)}`.toUpperCase();
}

const S_PUB32 = 0x110e;
const S_LPROC32 = 0x110f;
const S_GPROC32 = 0x1110;
const S_LDATA32 = 0x110c;
const S_GDATA32 = 0x110d;
const S_LTHREAD32 = 0x1112;
const S_GTHREAD32 = 0x1113;
const S_THUNK32 = 0x1102;

export function parsePdb(bytes: Uint8Array, sectionRvas: number[]): PdbInfo {
  const msf = new MsfFile(bytes);
  const info: PdbInfo = {
    guid: '',
    age: 0,
    signature: 0,
    blockSize: msf.blockSize,
    streamCount: msf.streams.length,
    modules: [],
    symbols: [],
  };

  // Stream 1: PDB info.
  const s1 = msf.streams[1];
  if (s1 && s1.length >= 28) {
    const r = new Reader(s1);
    info.signature = r.u32(4);
    info.age = r.u32(8);
    info.guid = guidFrom(r, 12);
  }

  // Stream 3: DBI.
  const dbi = msf.streams[3];
  let symRecordStream = -1;
  if (dbi && dbi.length >= 64) {
    const r = new Reader(dbi);
    symRecordStream = r.u16(20);
    info.machine = r.u16(62);
    const modInfoSize = r.i32(24);
    let p = 64;
    const end = Math.min(64 + Math.max(0, modInfoSize), dbi.length);
    let guard = 0;
    while (p + 64 <= end && guard++ < 60000) {
      const symByteSize = r.u32(p + 40);
      const name = r.cstr(p + 64, 1024);
      const objName = r.cstr(p + 64 + name.length + 1, 1024);
      info.modules.push({ name, objectFile: objName, symbolBytes: symByteSize });
      let next = p + 64 + name.length + 1 + objName.length + 1;
      next = (next + 3) & ~3;
      if (next <= p) break;
      p = next;
    }
  }

  const symStream = symRecordStream >= 0 ? msf.streams[symRecordStream] : undefined;
  if (symStream && symStream.length) {
    const r = new Reader(symStream);
    let p = 0;
    let guard = 0;
    while (p + 4 <= symStream.length && guard++ < 4_000_000) {
      const len = r.u16(p);
      if (len < 2) break;
      const kind = r.u16(p + 2);
      const recEnd = p + 2 + len;
      if (recEnd > symStream.length) break;
      let sym: Symbol | undefined;
      if (kind === S_PUB32) {
        const flags = r.u32(p + 4);
        const offset = r.u32(p + 8);
        const seg = r.u16(p + 12);
        const name = r.cstr(p + 14, recEnd - (p + 14));
        sym = mk(name, seg, offset, flags & 0x2 ? 'function' : 'public', sectionRvas);
      } else if (kind === S_GPROC32 || kind === S_LPROC32) {
        const length = r.u32(p + 4 + 12);
        const offset = r.u32(p + 4 + 28);
        const seg = r.u16(p + 4 + 32);
        const name = r.cstr(p + 4 + 35, recEnd - (p + 4 + 35));
        sym = mk(name, seg, offset, 'function', sectionRvas);
        if (sym) sym.size = length;
      } else if (kind === S_GDATA32 || kind === S_LDATA32 || kind === S_GTHREAD32 || kind === S_LTHREAD32) {
        const offset = r.u32(p + 8);
        const seg = r.u16(p + 12);
        const name = r.cstr(p + 14, recEnd - (p + 14));
        sym = mk(name, seg, offset, 'data', sectionRvas);
      } else if (kind === S_THUNK32) {
        const offset = r.u32(p + 16);
        const seg = r.u16(p + 20);
        const name = r.cstr(p + 23, recEnd - (p + 23));
        sym = mk(name, seg, offset, 'thunk', sectionRvas);
      }
      if (sym) info.symbols.push(sym);
      p = recEnd;
      if (len % 4 === 3) p += 1;
    }
  }

  info.symbols.sort((a, b) => a.rva - b.rva);
  return info;
}

function mk(
  name: string,
  seg: number,
  offset: number,
  kind: Symbol['kind'],
  sectionRvas: number[],
): Symbol | undefined {
  if (!name) return undefined;
  const base = sectionRvas[seg - 1];
  if (base === undefined) return undefined;
  return {
    name,
    pretty: prettifySymbol(name),
    rva: base + offset,
    section: seg - 1,
    offset,
    kind,
    source: 'pdb',
  };
}

/** MSVC linker .map files: "0001:00001234  ?foo@@YAXXZ  0000000180001234 f  obj.obj" */
export function parseMapFile(text: string, sectionRvas: number[]): Symbol[] {
  const out: Symbol[] = [];
  const lines = text.split(/\r?\n/);
  const re = /^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})\s+(\S+)\s+([0-9A-Fa-f]{8,16})?\s*(f\s+)?(?:i\s+)?(.*)$/;
  for (const line of lines) {
    const m = re.exec(line);
    if (!m) continue;
    const seg = parseInt(m[1], 16);
    const offset = parseInt(m[2], 16);
    const name = m[3];
    if (!name || name === 'Publics') continue;
    const base = sectionRvas[seg - 1];
    if (base === undefined) continue;
    out.push({
      name,
      pretty: prettifySymbol(name),
      rva: base + offset,
      section: seg - 1,
      offset,
      kind: m[5] ? 'function' : 'map',
      moduleName: (m[6] || '').trim() || undefined,
      source: 'map',
    });
  }
  out.sort((a, b) => a.rva - b.rva);
  return out;
}
