import { Reader, hex, hexBig, formatSize } from './reader';
import {
  DATA_DIRECTORY_NAMES,
  DEBUG_TYPE,
  DLL_CHARACTERISTICS,
  FILE_CHARACTERISTICS,
  MACHINE,
  RELOC_TYPE,
  RESOURCE_TYPE,
  RICH_PRODUCT,
  SECTION_FLAGS,
  SUBSYSTEM,
} from './constants';
import type {
  CLRInfo,
  DebugEntry,
  ExportInfo,
  ExportSymbol,
  Field,
  FieldGroup,
  ImportModule,
  ImportSymbol,
  MemoryRegion,
  PEImage,
  PESection,
  RelocBlock,
  ResourceNode,
  RichHeader,
  TLSInfo,
} from './types';
import { SECTION_COLORS, DIRECTORY_COLOR, colorForSection } from './colors';
import { describeSection } from '../knowledge/glossary';
import { entropyOf, entropyMap } from './entropy';

export class PEParseError extends Error {}

const flagList = (defs: { bit: number; name: string; desc: string }[], value: number) =>
  defs.map((d) => ({ name: d.name, desc: d.desc, set: (value & d.bit) !== 0 }));

const setFlagNames = (defs: { bit: number; name: string }[], value: number) =>
  defs.filter((d) => (value & d.bit) !== 0).map((d) => d.name);

const DIR_DESC = [
  'Functions and data this module makes available to others. Consumed by GetProcAddress and by other modules importing from this DLL.',
  'The list of DLLs and symbols this module needs. The loader resolves each one and writes the real address into the IAT.',
  'Icons, dialogs, string tables, version info, and manifests — a tree of binary blobs addressed by type/name/language.',
  'The .pdata table of RUNTIME_FUNCTION records used for table-driven stack unwinding on x64/ARM64. No SEH prologue cost at runtime.',
  'Authenticode signature blob. Note: this is a *file offset*, not an RVA — it is never mapped into memory.',
  'Base relocations (.reloc). If the loader cannot place the image at its preferred base, every absolute address listed here is patched.',
  'Pointers to debug records — most importantly the CodeView entry naming the matching PDB and its GUID/age.',
  'Reserved; must be zero.',
  'The RVA of the global pointer register value (IA64/MIPS).',
  'Thread Local Storage template: initial data for __declspec(thread) variables plus callbacks run on thread attach.',
  'Security cookie, SafeSEH table, Control Flow Guard function tables, and other loader-enforced hardening metadata.',
  'Pre-computed import addresses from a specific DLL version, used to skip resolution. Invalidated by ASLR.',
  'The Import Address Table: the array of function pointers patched by the loader. Calls go through these slots indirectly.',
  'Descriptors for delay-loaded DLLs — resolved on first call via a helper stub instead of at load time.',
  'The COR20 header marking this as a .NET assembly, pointing at CLI metadata.',
  'Reserved; must be zero.',
];

function computeChecksum(bytes: Uint8Array, checksumOffset: number): number {
  let sum = 0;
  const len = bytes.length;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i + 1 < len; i += 2) {
    if (i === checksumOffset || i === checksumOffset + 2) continue;
    sum += view.getUint16(i, true);
    if (sum > 0xffffffff) sum = (sum & 0xffffffff) + Math.floor(sum / 0x100000000);
  }
  if (len % 2) sum += bytes[len - 1];
  sum = (sum & 0xffff) + (sum >>> 16);
  sum = (sum & 0xffff) + (sum >>> 16);
  return (sum + len) >>> 0;
}

function timestamp(ts: number) {
  if (!ts) return '0 (not set)';
  if (ts > 0x60000000 && ts < 0x7fffffff) {
    // Heuristic: values in this band may be a reproducible-build hash rather than a date.
  }
  const d = new Date(ts * 1000);
  if (Number.isNaN(d.getTime())) return `${hex(ts)}`;
  return `${d.toISOString().replace('T', ' ').slice(0, 19)} UTC`;
}

export function parsePE(bytes: Uint8Array, fileName: string): PEImage {
  const r = new Reader(bytes);
  const warnings: string[] = [];

  if (bytes.length < 64) throw new PEParseError('File is too small to be a PE image.');
  if (r.u16(0) !== 0x5a4d) throw new PEParseError('Missing "MZ" DOS signature — this is not a PE file.');

  const peOffset = r.u32(0x3c);
  if (!r.canRead(24, peOffset)) throw new PEParseError(`e_lfanew (${hex(peOffset)}) points outside the file.`);
  if (r.u32(peOffset) !== 0x00004550) throw new PEParseError('Missing "PE\\0\\0" signature at e_lfanew.');

  const coffOff = peOffset + 4;
  const machine = r.u16(coffOff);
  const numberOfSections = r.u16(coffOff + 2);
  const timeDateStamp = r.u32(coffOff + 4);
  const pointerToSymbolTable = r.u32(coffOff + 8);
  const numberOfSymbols = r.u32(coffOff + 12);
  const sizeOfOptionalHeader = r.u16(coffOff + 16);
  const characteristics = r.u16(coffOff + 18);

  const optOff = coffOff + 20;
  const magic = r.u16(optOff);
  const is64 = magic === 0x20b;
  if (magic !== 0x10b && magic !== 0x20b) {
    if (magic === 0x107) throw new PEParseError('ROM images (magic 0x107) are not supported.');
    throw new PEParseError(`Unknown optional header magic ${hex(magic, 4)}.`);
  }

  const groups: FieldGroup[] = [];

  // ---------------- DOS header ----------------
  const dosFields: Field[] = [
    { name: 'e_magic', offset: 0, size: 2, value: '"MZ" (0x5A4D)', raw: 0x5a4d, desc: 'Mark Zbikowski\u2019s initials. Every PE still starts with the 1981 DOS header for backwards compatibility.' },
    { name: 'e_cblp', offset: 2, size: 2, value: hex(r.u16(2), 4), desc: 'Bytes on the last page of the DOS stub.' },
    { name: 'e_cp', offset: 4, size: 2, value: hex(r.u16(4), 4), desc: 'Pages in the DOS stub.' },
    { name: 'e_crlc', offset: 6, size: 2, value: hex(r.u16(6), 4), desc: 'DOS relocation count.' },
    { name: 'e_cparhdr', offset: 8, size: 2, value: hex(r.u16(8), 4), desc: 'Size of DOS header in paragraphs.' },
    { name: 'e_lfarlc', offset: 0x18, size: 2, value: hex(r.u16(0x18), 4), desc: 'File offset of the DOS relocation table.' },
    { name: 'e_ovno', offset: 0x1a, size: 2, value: hex(r.u16(0x1a), 4), desc: 'Overlay number.' },
    { name: 'e_lfanew', offset: 0x3c, size: 4, value: hex(peOffset), raw: peOffset, desc: 'The bridge to the modern world: file offset of the PE signature.' },
  ];
  groups.push({
    id: 'dos',
    title: 'DOS Header',
    offset: 0,
    size: 64,
    desc: 'A vestigial MS-DOS EXE header. Windows only reads two fields from it: the MZ magic and e_lfanew.',
    fields: dosFields,
  });

  // DOS stub
  const stubStart = 64;
  const stubEnd = peOffset;
  if (stubEnd > stubStart) {
    const stubText = r.cstr(stubStart, Math.min(200, stubEnd - stubStart));
    groups.push({
      id: 'dosstub',
      title: 'DOS Stub',
      offset: stubStart,
      size: stubEnd - stubStart,
      desc: 'A tiny real-mode program that runs if you execute the file under MS-DOS. It just prints a message and exits.',
      fields: [
        {
          name: 'stub message',
          offset: stubStart,
          size: stubEnd - stubStart,
          value: findAsciiRun(r, stubStart, stubEnd) || stubText || '(binary)',
          desc: 'The classic "This program cannot be run in DOS mode." string lives here.',
        },
      ],
    });
  }

  // ---------------- Rich header ----------------
  const rich = parseRich(r, peOffset);

  // ---------------- COFF ----------------
  const machineName = MACHINE[machine] ?? `Unknown (${hex(machine, 4)})`;
  const characteristicFlags = flagList(FILE_CHARACTERISTICS, characteristics);
  groups.push({
    id: 'coff',
    title: 'COFF File Header',
    offset: coffOff,
    size: 20,
    desc: 'The classic 20-byte COFF header: what CPU this targets, how many sections follow, and coarse file attributes.',
    fields: [
      { name: 'Signature', offset: peOffset, size: 4, value: '"PE\\0\\0"', desc: 'Confirms a Portable Executable image.' },
      { name: 'Machine', offset: coffOff, size: 2, value: `${machineName} (${hex(machine, 4)})`, raw: machine, desc: 'Target CPU architecture. The loader refuses images that do not match the process.' },
      { name: 'NumberOfSections', offset: coffOff + 2, size: 2, value: String(numberOfSections), raw: numberOfSections, desc: 'How many section headers follow the optional header.' },
      { name: 'TimeDateStamp', offset: coffOff + 4, size: 4, value: timestamp(timeDateStamp), raw: timeDateStamp, desc: 'Link time as a Unix epoch — or, in reproducible builds, a hash of the inputs.' },
      { name: 'PointerToSymbolTable', offset: coffOff + 8, size: 4, value: hex(pointerToSymbolTable), raw: pointerToSymbolTable, desc: 'Deprecated COFF symbol table offset. Should be 0 in images.' },
      { name: 'NumberOfSymbols', offset: coffOff + 12, size: 4, value: String(numberOfSymbols), raw: numberOfSymbols, desc: 'Deprecated COFF symbol count. Should be 0 in images.' },
      { name: 'SizeOfOptionalHeader', offset: coffOff + 16, size: 2, value: `${sizeOfOptionalHeader} bytes`, raw: sizeOfOptionalHeader, desc: 'Length of the optional header — tells you where the section table starts.' },
      {
        name: 'Characteristics',
        offset: coffOff + 18,
        size: 2,
        value: hex(characteristics, 4),
        raw: characteristics,
        desc: 'Bit flags describing the image at a high level.',
        flags: characteristicFlags,
      },
    ],
  });

  // ---------------- Optional header ----------------
  const o = (off: number) => optOff + off;
  const majorLinker = r.u8(o(2));
  const minorLinker = r.u8(o(3));
  const sizeOfCode = r.u32(o(4));
  const sizeOfInitData = r.u32(o(8));
  const sizeOfUninitData = r.u32(o(12));
  const entryPoint = r.u32(o(16));
  const baseOfCode = r.u32(o(20));
  const baseOfData = is64 ? 0 : r.u32(o(24));
  const imageBase = is64 ? r.u64(o(24)) : r.u32(o(28));
  const varOff = is64 ? 32 : 32;
  const sectionAlignment = r.u32(o(varOff));
  const fileAlignment = r.u32(o(varOff + 4));
  const majorOS = r.u16(o(varOff + 8));
  const minorOS = r.u16(o(varOff + 10));
  const majorImage = r.u16(o(varOff + 12));
  const minorImage = r.u16(o(varOff + 14));
  const majorSubsystem = r.u16(o(varOff + 16));
  const minorSubsystem = r.u16(o(varOff + 18));
  const win32Version = r.u32(o(varOff + 20));
  const sizeOfImage = r.u32(o(varOff + 24));
  const sizeOfHeaders = r.u32(o(varOff + 28));
  const checksumOffset = o(varOff + 32);
  const checksum = r.u32(checksumOffset);
  const subsystem = r.u16(o(varOff + 36));
  const dllCharacteristics = r.u16(o(varOff + 38));
  const stackReserve = is64 ? r.u64(o(varOff + 40)) : r.u32(o(varOff + 40));
  const stackCommit = is64 ? r.u64(o(varOff + 48)) : r.u32(o(varOff + 44));
  const heapReserve = is64 ? r.u64(o(varOff + 56)) : r.u32(o(varOff + 48));
  const heapCommit = is64 ? r.u64(o(varOff + 64)) : r.u32(o(varOff + 52));
  const loaderFlagsOff = is64 ? varOff + 72 : varOff + 56;
  const loaderFlags = r.u32(o(loaderFlagsOff));
  const numberOfRvaAndSizes = r.u32(o(loaderFlagsOff + 4));
  const dirOff = o(loaderFlagsOff + 8);

  const dllCharacteristicFlags = flagList(DLL_CHARACTERISTICS, dllCharacteristics);
  const subsystemName = SUBSYSTEM[subsystem] ?? `Unknown (${subsystem})`;

  const optFields: Field[] = [
    { name: 'Magic', offset: o(0), size: 2, value: is64 ? 'PE32+ (0x20B, 64-bit)' : 'PE32 (0x10B, 32-bit)', raw: magic, desc: 'Distinguishes 32-bit (PE32) from 64-bit (PE32+) layout. It changes the size of several later fields.' },
    { name: 'LinkerVersion', offset: o(2), size: 2, value: `${majorLinker}.${minorLinker}`, desc: 'Version of link.exe (or lld) that produced the image.' },
    { name: 'SizeOfCode', offset: o(4), size: 4, value: formatSize(sizeOfCode), raw: sizeOfCode, desc: 'Total size of all executable sections.' },
    { name: 'SizeOfInitializedData', offset: o(8), size: 4, value: formatSize(sizeOfInitData), raw: sizeOfInitData, desc: 'Total size of initialized data sections stored in the file.' },
    { name: 'SizeOfUninitializedData', offset: o(12), size: 4, value: formatSize(sizeOfUninitData), raw: sizeOfUninitData, desc: 'BSS size — zero-filled by the loader, costs nothing on disk.' },
    { name: 'AddressOfEntryPoint', offset: o(16), size: 4, value: hex(entryPoint), raw: entryPoint, desc: 'RVA of DllMain (for a DLL) or main-crt-startup (for an EXE). Zero is legal for resource-only DLLs.' },
    { name: 'BaseOfCode', offset: o(20), size: 4, value: hex(baseOfCode), raw: baseOfCode, desc: 'RVA where the code sections begin.' },
    ...(is64 ? [] : [{ name: 'BaseOfData', offset: o(24), size: 4, value: hex(baseOfData), raw: baseOfData, desc: 'RVA where the data sections begin. PE32 only — PE32+ dropped it.' } as Field]),
    { name: 'ImageBase', offset: o(is64 ? 24 : 28), size: is64 ? 8 : 4, value: hexBig(imageBase, is64 ? 16 : 8), raw: imageBase, desc: 'Preferred load address. With ASLR the loader will usually pick a different base and apply relocations.' },
    { name: 'SectionAlignment', offset: o(varOff), size: 4, value: `${formatSize(sectionAlignment)} (${hex(sectionAlignment)})`, raw: sectionAlignment, desc: 'Alignment of sections once mapped into memory — normally the 4 KB page size, so each section gets its own protection.' },
    { name: 'FileAlignment', offset: o(varOff + 4), size: 4, value: `${formatSize(fileAlignment)} (${hex(fileAlignment)})`, raw: fileAlignment, desc: 'Alignment of raw section data on disk — usually 512 bytes (one sector).' },
    { name: 'OS Version', offset: o(varOff + 8), size: 4, value: `${majorOS}.${minorOS}`, desc: 'Minimum required operating system version.' },
    { name: 'Image Version', offset: o(varOff + 12), size: 4, value: `${majorImage}.${minorImage}`, desc: 'User-defined image version (/VERSION linker switch).' },
    { name: 'Subsystem Version', offset: o(varOff + 16), size: 4, value: `${majorSubsystem}.${minorSubsystem}`, desc: 'Minimum subsystem version. Bumping this can block the image from loading on older Windows.' },
    { name: 'Win32VersionValue', offset: o(varOff + 20), size: 4, value: hex(win32Version), raw: win32Version, desc: 'Reserved; must be zero.' },
    { name: 'SizeOfImage', offset: o(varOff + 24), size: 4, value: `${formatSize(sizeOfImage)} (${hex(sizeOfImage)})`, raw: sizeOfImage, desc: 'Total bytes of address space the loader reserves for this module — the height of the whole memory map.' },
    { name: 'SizeOfHeaders', offset: o(varOff + 28), size: 4, value: `${formatSize(sizeOfHeaders)} (${hex(sizeOfHeaders)})`, raw: sizeOfHeaders, desc: 'Combined size of all headers, rounded up to FileAlignment. Section raw data starts after this.' },
    { name: 'CheckSum', offset: checksumOffset, size: 4, value: hex(checksum), raw: checksum, desc: 'Image checksum. Enforced for drivers and any DLL loaded into a critical system process.' },
    { name: 'Subsystem', offset: o(varOff + 36), size: 2, value: `${subsystemName} (${subsystem})`, raw: subsystem, desc: 'Which Windows subsystem is required to run the image.' },
    {
      name: 'DllCharacteristics',
      offset: o(varOff + 38),
      size: 2,
      value: hex(dllCharacteristics, 4),
      raw: dllCharacteristics,
      desc: 'The security-mitigation bitfield: ASLR, DEP, CFG, SafeSEH and friends live here.',
      flags: dllCharacteristicFlags,
    },
    { name: 'SizeOfStackReserve', offset: o(varOff + 40), size: is64 ? 8 : 4, value: formatSize(stackReserve), raw: stackReserve, desc: 'Virtual address space reserved for the initial thread stack.' },
    { name: 'SizeOfStackCommit', offset: o(varOff + (is64 ? 48 : 44)), size: is64 ? 8 : 4, value: formatSize(stackCommit), raw: stackCommit, desc: 'Stack memory committed up front; the rest grows on demand via guard pages.' },
    { name: 'SizeOfHeapReserve', offset: o(varOff + (is64 ? 56 : 48)), size: is64 ? 8 : 4, value: formatSize(heapReserve), raw: heapReserve, desc: 'Address space reserved for the default process heap.' },
    { name: 'SizeOfHeapCommit', offset: o(varOff + (is64 ? 64 : 52)), size: is64 ? 8 : 4, value: formatSize(heapCommit), raw: heapCommit, desc: 'Default heap memory committed at startup.' },
    { name: 'LoaderFlags', offset: o(loaderFlagsOff), size: 4, value: hex(loaderFlags), raw: loaderFlags, desc: 'Obsolete; must be zero.' },
    { name: 'NumberOfRvaAndSizes', offset: o(loaderFlagsOff + 4), size: 4, value: String(numberOfRvaAndSizes), raw: numberOfRvaAndSizes, desc: 'How many data directory entries follow. Effectively always 16.' },
  ];

  groups.push({
    id: 'optional',
    title: is64 ? 'Optional Header (PE32+)' : 'Optional Header (PE32)',
    offset: optOff,
    size: sizeOfOptionalHeader,
    desc: 'Despite the name it is mandatory for images. This is where the loader learns the entry point, the preferred base, alignments, and the security posture.',
    fields: optFields,
  });

  // ---------------- Data directories ----------------
  const dirCount = Math.min(numberOfRvaAndSizes, 16);
  const dataDirectories = [] as PEImage['dataDirectories'];
  for (let i = 0; i < dirCount; i++) {
    const at = dirOff + i * 8;
    if (!r.canRead(8, at)) break;
    dataDirectories.push({
      index: i,
      name: DATA_DIRECTORY_NAMES[i] ?? `Directory ${i}`,
      rva: r.u32(at),
      size: r.u32(at + 4),
      desc: DIR_DESC[i] ?? '',
    });
  }

  // ---------------- Sections ----------------
  const secOff = optOff + sizeOfOptionalHeader;
  const sections: PESection[] = [];
  for (let i = 0; i < numberOfSections; i++) {
    const at = secOff + i * 40;
    if (!r.canRead(40, at)) {
      warnings.push(`Section table is truncated at entry ${i}.`);
      break;
    }
    let name = r.fixedAscii(at, 8);
    if (name.startsWith('/')) {
      // Long section name stored in the COFF string table (object files / some linkers).
      name = `${name} (long name)`;
    }
    const virtualSize = r.u32(at + 8);
    const virtualAddress = r.u32(at + 12);
    const rawSize = r.u32(at + 16);
    const rawPointer = r.u32(at + 20);
    const relocPointer = r.u32(at + 24);
    const numberOfRelocations = r.u16(at + 32);
    const ch = r.u32(at + 36);
    const data = r.bytesAt(rawPointer, Math.min(rawSize, Math.max(0, bytes.length - rawPointer)));
    const perms =
      ((ch & 0x40000000) ? 'R' : '-') + ((ch & 0x80000000) ? 'W' : '-') + ((ch & 0x20000000) ? 'X' : '-');
    sections.push({
      index: i,
      name,
      virtualAddress,
      virtualSize,
      rawPointer,
      rawSize,
      characteristics: ch,
      flagNames: setFlagNames(SECTION_FLAGS, ch),
      perms,
      entropy: entropyOf(data),
      entropyMap: entropyMap(data, 96),
      relocPointer,
      numberOfRelocations,
      desc: describeSection(name),
      slack: Math.max(0, rawSize - virtualSize),
    });
    if (rawPointer + rawSize > bytes.length) {
      warnings.push(`Section "${name}" claims raw data past the end of the file — the file may be truncated.`);
    }
    if (perms === 'RWX') {
      warnings.push(`Section "${name}" is readable, writable AND executable — a classic packer/exploit signature.`);
    }
  }

  const rvaToOffset = (rva: number): number => {
    if (rva < sizeOfHeaders && sections.every((s) => rva < s.virtualAddress)) return rva;
    for (const s of sections) {
      const vsize = s.virtualSize || s.rawSize;
      if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(vsize, s.rawSize)) {
        const delta = rva - s.virtualAddress;
        if (delta >= s.rawSize) return -1; // lives in the zero-filled tail
        return s.rawPointer + delta;
      }
    }
    if (rva < sizeOfHeaders) return rva;
    return -1;
  };

  const sectionOfRva = (rva: number) =>
    sections.find(
      (s) => rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize || s.rawSize, s.rawSize),
    );

  const safe = <T,>(what: string, fn: () => T): T | undefined => {
    try {
      return fn();
    } catch (e) {
      warnings.push(`Failed to parse ${what}: ${(e as Error).message}`);
      return undefined;
    }
  };

  const dir = (i: number) => dataDirectories[i] ?? { rva: 0, size: 0 };

  // ---------------- Imports ----------------
  const imports: ImportModule[] = [];
  const importDir = dir(1);
  if (importDir.rva && importDir.size) {
    safe('the import table', () => {
      let at = rvaToOffset(importDir.rva);
      let guard = 0;
      while (at >= 0 && r.canRead(20, at) && guard++ < 4096) {
        const oft = r.u32(at);
        const tds = r.u32(at + 4);
        const fwd = r.u32(at + 8);
        const nameRva = r.u32(at + 12);
        const ft = r.u32(at + 16);
        if (!oft && !nameRva && !ft) break;
        const nameOff = rvaToOffset(nameRva);
        const dll = nameOff >= 0 ? r.cstr(nameOff, 256) : `<bad name RVA ${hex(nameRva)}>`;
        imports.push({
          dll,
          descriptorRva: importDir.rva + (at - rvaToOffset(importDir.rva)),
          originalFirstThunk: oft,
          firstThunk: ft,
          timeDateStamp: tds,
          forwarderChain: fwd,
          delayLoaded: false,
          category: categorizeDll(dll),
          symbols: readThunks(r, rvaToOffset, oft || ft, ft, is64, dll),
        });
        at += 20;
      }
    });
  }

  // ---------------- Delay imports ----------------
  const delayDir = dir(13);
  if (delayDir.rva && delayDir.size) {
    safe('the delay-load import table', () => {
      let at = rvaToOffset(delayDir.rva);
      let guard = 0;
      while (at >= 0 && r.canRead(32, at) && guard++ < 2048) {
        const attrs = r.u32(at);
        const nameRva = r.u32(at + 4);
        const iat = r.u32(at + 12);
        const int = r.u32(at + 16);
        if (!nameRva) break;
        // attrs bit0 set => RVAs; otherwise legacy VAs.
        const toRva = (v: number) => (attrs & 1 ? v : Math.max(0, v - imageBase));
        const nameOff = rvaToOffset(toRva(nameRva));
        const dll = nameOff >= 0 ? r.cstr(nameOff, 256) : `<bad name RVA>`;
        imports.push({
          dll,
          descriptorRva: delayDir.rva,
          originalFirstThunk: toRva(int),
          firstThunk: toRva(iat),
          timeDateStamp: 0,
          forwarderChain: 0,
          delayLoaded: true,
          category: categorizeDll(dll),
          symbols: readThunks(r, rvaToOffset, toRva(int) || toRva(iat), toRva(iat), is64, dll),
        });
        at += 32;
      }
    });
  }

  // ---------------- Exports ----------------
  let exportsInfo: ExportInfo | undefined;
  const expDir = dir(0);
  if (expDir.rva && expDir.size) {
    exportsInfo = safe('the export table', () => {
      const at = rvaToOffset(expDir.rva);
      if (at < 0 || !r.canRead(40, at)) throw new Error('export directory is outside the file');
      const timeStamp = r.u32(at + 4);
      const nameRva = r.u32(at + 12);
      const ordinalBase = r.u32(at + 16);
      const numberOfFunctions = r.u32(at + 20);
      const numberOfNames = r.u32(at + 24);
      const addressTableRva = r.u32(at + 28);
      const namePointerRva = r.u32(at + 32);
      const ordinalTableRva = r.u32(at + 36);
      const nameOff = rvaToOffset(nameRva);
      const dllName = nameOff >= 0 ? r.cstr(nameOff, 256) : fileName;

      const funcs: ExportSymbol[] = [];
      const addrOff = rvaToOffset(addressTableRva);
      const cap = Math.min(numberOfFunctions, 200000);
      for (let i = 0; i < cap; i++) {
        if (addrOff < 0 || !r.canRead(4, addrOff + i * 4)) break;
        const rva = r.u32(addrOff + i * 4);
        if (!rva) continue;
        const isForwarder = rva >= expDir.rva && rva < expDir.rva + expDir.size;
        const fo = rvaToOffset(rva);
        funcs.push({
          ordinal: ordinalBase + i,
          rva,
          forwarder: isForwarder && fo >= 0 ? r.cstr(fo, 256) : undefined,
          section: sectionOfRva(rva)?.name,
        });
      }

      const nameOffTable = rvaToOffset(namePointerRva);
      const ordOffTable = rvaToOffset(ordinalTableRva);
      const nameCap = Math.min(numberOfNames, 200000);
      for (let i = 0; i < nameCap; i++) {
        if (nameOffTable < 0 || ordOffTable < 0) break;
        if (!r.canRead(4, nameOffTable + i * 4) || !r.canRead(2, ordOffTable + i * 2)) break;
        const nRva = r.u32(nameOffTable + i * 4);
        const ord = r.u16(ordOffTable + i * 2);
        const no = rvaToOffset(nRva);
        const nm = no >= 0 ? r.cstr(no, 512) : undefined;
        const target = funcs.find((f) => f.ordinal === ordinalBase + ord);
        if (target) {
          target.name = nm;
          target.nameRva = nRva;
        }
      }
      funcs.sort((a, b) => a.ordinal - b.ordinal);
      return {
        dllName,
        timeDateStamp: timeStamp,
        ordinalBase,
        numberOfFunctions,
        numberOfNames,
        addressTableRva,
        namePointerRva,
        ordinalTableRva,
        symbols: funcs,
      };
    });
  }

  // ---------------- Relocations ----------------
  const relocations: RelocBlock[] = [];
  let relocCount = 0;
  const relDir = dir(5);
  if (relDir.rva && relDir.size) {
    safe('base relocations', () => {
      const start = rvaToOffset(relDir.rva);
      let at = start;
      const end = start + relDir.size;
      let guard = 0;
      while (at >= 0 && at + 8 <= end && r.canRead(8, at) && guard++ < 100000) {
        const pageRva = r.u32(at);
        const sizeOfBlock = r.u32(at + 4);
        if (sizeOfBlock < 8 || at + sizeOfBlock > end + 8) break;
        const count = (sizeOfBlock - 8) / 2;
        const entries: RelocBlock['entries'] = [];
        for (let i = 0; i < count; i++) {
          if (!r.canRead(2, at + 8 + i * 2)) break;
          const v = r.u16(at + 8 + i * 2);
          const type = v >> 12;
          const off = v & 0xfff;
          if (type !== 0) relocCount++;
          if (entries.length < 4096) {
            entries.push({ type, typeName: RELOC_TYPE[type] ?? `Type ${type}`, offset: off, rva: pageRva + off });
          }
        }
        relocations.push({ pageRva, sizeOfBlock, entries });
        at += sizeOfBlock;
      }
    });
  }

  // ---------------- Resources ----------------
  let resources: ResourceNode | undefined;
  let resourceCount = 0;
  const resDir = dir(2);
  if (resDir.rva && resDir.size) {
    resources = safe('the resource tree', () => {
      const base = rvaToOffset(resDir.rva);
      if (base < 0) throw new Error('resource directory is outside the file');
      const counter = { n: 0 };
      const node = readResourceDir(r, base, base, 0, rvaToOffset, counter);
      resourceCount = counter.n;
      return node;
    });
  }

  // ---------------- Debug ----------------
  const debug: DebugEntry[] = [];
  const dbgDir = dir(6);
  if (dbgDir.rva && dbgDir.size) {
    safe('the debug directory', () => {
      const base = rvaToOffset(dbgDir.rva);
      const count = Math.floor(dbgDir.size / 28);
      for (let i = 0; i < count && i < 64; i++) {
        const at = base + i * 28;
        if (base < 0 || !r.canRead(28, at)) break;
        const type = r.u32(at + 12);
        const sizeOfData = r.u32(at + 16);
        const addressOfRawData = r.u32(at + 20);
        const pointerToRawData = r.u32(at + 24);
        const e: DebugEntry = {
          type,
          typeName: DEBUG_TYPE[type] ?? `Type ${type}`,
          timeDateStamp: r.u32(at + 4),
          sizeOfData,
          addressOfRawData,
          pointerToRawData,
        };
        if (type === 2 && r.canRead(24, pointerToRawData)) {
          const sig = r.u32(pointerToRawData);
          if (sig === 0x53445352) {
            // 'RSDS'
            e.signature = 'RSDS';
            e.guid = formatGuid(r, pointerToRawData + 4);
            e.age = r.u32(pointerToRawData + 20);
            e.pdbPath = r.cstr(pointerToRawData + 24, 512);
          } else if (sig === 0x3031424e) {
            e.signature = 'NB10';
            e.age = r.u32(pointerToRawData + 12);
            e.pdbPath = r.cstr(pointerToRawData + 16, 512);
          }
        }
        debug.push(e);
      }
    });
  }

  // ---------------- TLS ----------------
  let tls: TLSInfo | undefined;
  const tlsDir = dir(9);
  if (tlsDir.rva && tlsDir.size) {
    tls = safe('the TLS directory', () => {
      const at = rvaToOffset(tlsDir.rva);
      if (at < 0) throw new Error('TLS directory is outside the file');
      const rd = (n: number) => (is64 ? r.u64(at + n * 8) : r.u32(at + n * 4));
      const startAddressOfRawData = rd(0);
      const endAddressOfRawData = rd(1);
      const addressOfIndex = rd(2);
      const addressOfCallbacks = rd(3);
      const tail = is64 ? at + 32 : at + 16;
      const sizeOfZeroFill = r.u32(tail);
      const characteristics2 = r.u32(tail + 4);
      const callbacks: number[] = [];
      if (addressOfCallbacks > imageBase) {
        const cbOff = rvaToOffset(addressOfCallbacks - imageBase);
        for (let i = 0; cbOff >= 0 && i < 64; i++) {
          const p = is64 ? r.u64(cbOff + i * 8) : r.u32(cbOff + i * 4);
          if (!p) break;
          callbacks.push(p);
        }
      }
      return {
        startAddressOfRawData,
        endAddressOfRawData,
        addressOfIndex,
        addressOfCallbacks,
        sizeOfZeroFill,
        characteristics: characteristics2,
        callbacks,
      };
    });
  }

  // ---------------- .NET / CLR ----------------
  let clr: CLRInfo | undefined;
  const clrDir = dir(14);
  if (clrDir.rva && clrDir.size) {
    clr = safe('the CLR header', () => {
      const at = rvaToOffset(clrDir.rva);
      if (at < 0) throw new Error('CLR header is outside the file');
      const cb = r.u32(at);
      const major = r.u16(at + 4);
      const minor = r.u16(at + 6);
      const metadataRva = r.u32(at + 8);
      const metadataSize = r.u32(at + 12);
      const flags = r.u32(at + 16);
      const entryPointToken = r.u32(at + 20);
      const names: string[] = [];
      if (flags & 1) names.push('ILONLY');
      if (flags & 2) names.push('32BITREQUIRED');
      if (flags & 8) names.push('STRONGNAMESIGNED');
      if (flags & 0x10) names.push('NATIVE_ENTRYPOINT');
      if (flags & 0x10000) names.push('TRACKDEBUGDATA');
      if (flags & 0x20000) names.push('32BITPREFERRED');
      const md = rvaToOffset(metadataRva);
      let metadataVersion: string | undefined;
      const streams: { name: string; offset: number; size: number }[] = [];
      if (md >= 0 && r.canRead(20, md) && r.u32(md) === 0x424a5342) {
        const verLen = r.u32(md + 12);
        metadataVersion = r.cstr(md + 16, Math.min(verLen, 256));
        let p = md + 16 + verLen + 2;
        const nStreams = r.u16(p);
        p += 2;
        for (let i = 0; i < nStreams && i < 16; i++) {
          const so = r.u32(p);
          const ss = r.u32(p + 4);
          const nm = r.cstr(p + 8, 32);
          streams.push({ name: nm, offset: so, size: ss });
          p += 8 + Math.ceil((nm.length + 1) / 4) * 4;
        }
      }
      return {
        cb,
        runtimeVersion: `${major}.${minor}`,
        metadataRva,
        metadataSize,
        flags,
        flagNames: names,
        entryPointToken,
        metadataVersion,
        streams,
      };
    });
  }

  // ---------------- Load config ----------------
  let loadConfig: Field[] | undefined;
  const lcDir = dir(10);
  if (lcDir.rva && lcDir.size) {
    loadConfig = safe('the load config directory', () => {
      const at = rvaToOffset(lcDir.rva);
      if (at < 0) throw new Error('load config is outside the file');
      const ptr = (n: number) => (is64 ? r.u64(at + n) : r.u32(at + n));
      const f: Field[] = [];
      const size = r.u32(at);
      f.push({ name: 'Size', offset: at, size: 4, value: `${size} bytes`, raw: size, desc: 'Size of this structure — it grew with every Windows release, so the size tells you which fields are valid.' });
      const cookieOff = is64 ? 0x58 : 0x3c;
      if (size > cookieOff) {
        const cookie = ptr(cookieOff);
        f.push({ name: 'SecurityCookie', offset: at + cookieOff, size: is64 ? 8 : 4, value: hexBig(cookie, is64 ? 16 : 8), raw: cookie, desc: 'VA of the /GS stack cookie. The CRT randomizes it at startup; every guarded function checks it before returning.' });
      }
      const sehOff = is64 ? 0x60 : 0x40;
      if (!is64 && size > sehOff + 4) {
        const sehTable = ptr(sehOff);
        const sehCount = ptr(sehOff + 4);
        f.push({ name: 'SEHandlerTable', offset: at + sehOff, size: 4, value: hex(sehTable), raw: sehTable, desc: 'SafeSEH: a sorted table of legal exception handler RVAs. Anything not listed is rejected at dispatch time.' });
        f.push({ name: 'SEHandlerCount', offset: at + sehOff + 4, size: 4, value: String(sehCount), raw: sehCount, desc: 'Number of registered SafeSEH handlers.' });
      }
      const cfgOff = is64 ? 0x70 : 0x48;
      if (size > cfgOff + 16) {
        const cfCheck = ptr(cfgOff);
        const cfTable = ptr(cfgOff + (is64 ? 16 : 8));
        f.push({ name: 'GuardCFCheckFunctionPointer', offset: at + cfgOff, size: is64 ? 8 : 4, value: hexBig(cfCheck, is64 ? 16 : 8), raw: cfCheck, desc: 'VA of the slot holding _guard_check_icall — the loader patches it to the real CFG validator.' });
        f.push({ name: 'GuardCFFunctionTable', offset: at + cfgOff + (is64 ? 16 : 8), size: is64 ? 8 : 4, value: hexBig(cfTable, is64 ? 16 : 8), raw: cfTable, desc: 'Table of every address that is a legal indirect-call target.' });
      }
      return f;
    });
  }

  // ---------------- Certificates ----------------
  const certificates: PEImage['certificates'] = [];
  const certDir = dir(4);
  if (certDir.rva && certDir.size) {
    safe('the certificate table', () => {
      let at = certDir.rva; // file offset, not RVA
      const end = Math.min(at + certDir.size, bytes.length);
      let guard = 0;
      while (at + 8 <= end && guard++ < 32) {
        const len = r.u32(at);
        const rev = r.u16(at + 4);
        const type = r.u16(at + 6);
        if (len < 8) break;
        certificates.push({
          offset: at,
          size: len,
          revision: rev,
          type: type === 2 ? 'PKCS#7 SignedData (Authenticode)' : `Type ${type}`,
        });
        at += (len + 7) & ~7;
      }
    });
  }

  // ---------------- Version info ----------------
  const versionInfo = resources ? extractVersionInfo(r, resources, rvaToOffset) : undefined;

  // A deterministic build stores a content hash in TimeDateStamp rather than a date.
  const reproducibleBuild =
    debug.some((d) => d.type === 16) || timeDateStamp > Math.floor(Date.now() / 1000) + 86400;
  if (reproducibleBuild) {
    const f = groups.find((g) => g.id === 'coff')?.fields.find((x) => x.name === 'TimeDateStamp');
    if (f) {
      f.value = `${hex(timeDateStamp)} — deterministic build hash, not a date`;
      f.desc =
        'This image was built reproducibly, so the linker replaced the link time with a hash of the build inputs. Two identical builds produce identical files.';
    }
  }

  // ---------------- Regions ----------------
  const memoryRegions = buildMemoryRegions(sections, sizeOfHeaders, sizeOfImage, sectionAlignment, dataDirectories);
  const fileRegions = buildFileRegions(sections, sizeOfHeaders, bytes.length, certDir);

  const computedChecksum = computeChecksum(bytes, checksumOffset);
  if (checksum !== 0 && checksum !== computedChecksum) {
    warnings.push(
      `CheckSum mismatch: header says ${hex(checksum)} but the file computes to ${hex(computedChecksum)}. The file was modified after linking (or is signed and patched).`,
    );
  }
  if ((dllCharacteristics & 0x0040) && !relDir.rva) {
    warnings.push('DYNAMIC_BASE (ASLR) is set but there is no relocation directory — the image cannot actually be rebased.');
  }
  if (entryPoint === 0 && (characteristics & 0x2000)) {
    warnings.push('No entry point: this is a resource-only DLL (no DllMain runs).');
  }

  return {
    fileName,
    fileSize: bytes.length,
    bytes,
    is64,
    isDll: (characteristics & 0x2000) !== 0,
    machine,
    machineName,
    peOffset,
    imageBase,
    entryPoint,
    sizeOfImage,
    sizeOfHeaders,
    sectionAlignment,
    fileAlignment,
    subsystem,
    subsystemName,
    timeDateStamp,
    checksum,
    computedChecksum,
    groups,
    dataDirectories,
    sections,
    imports,
    exports: exportsInfo,
    relocations,
    relocCount,
    resources,
    resourceCount,
    debug,
    tls,
    clr,
    loadConfig,
    rich,
    certificates,
    memoryRegions,
    fileRegions,
    characteristics,
    characteristicFlags,
    dllCharacteristics,
    dllCharacteristicFlags,
    warnings,
    entropy: entropyOf(bytes),
    versionInfo,
    hasCFG: (dllCharacteristics & 0x4000) !== 0,
    hasASLR: (dllCharacteristics & 0x0040) !== 0,
    hasDEP: (dllCharacteristics & 0x0100) !== 0,
    hasSEH: (dllCharacteristics & 0x0400) === 0,
    hasAuthenticode: certificates.length > 0,
    isDotNet: !!clr,
    reproducibleBuild,
  };
}

function findAsciiRun(r: Reader, start: number, end: number) {
  let best = '';
  let cur = '';
  for (let i = start; i < end; i++) {
    const c = r.bytes[i];
    if (c >= 0x20 && c < 0x7f) cur += String.fromCharCode(c);
    else {
      if (cur.length > best.length) best = cur;
      cur = '';
    }
  }
  if (cur.length > best.length) best = cur;
  return best.trim();
}

function readThunks(
  r: Reader,
  rvaToOffset: (rva: number) => number,
  thunkRva: number,
  iatRva: number,
  is64: boolean,
  dll: string,
): ImportSymbol[] {
  const out: ImportSymbol[] = [];
  if (!thunkRva) return out;
  const step = is64 ? 8 : 4;
  const base = rvaToOffset(thunkRva);
  const iatBase = rvaToOffset(iatRva);
  if (base < 0) return out;
  const ordinalFlag = is64 ? 0x8000000000000000 : 0x80000000;
  for (let i = 0; i < 65536; i++) {
    const at = base + i * step;
    if (!r.canRead(step, at)) break;
    const v = is64 ? r.u64(at) : r.u32(at);
    if (!v) break;
    const byOrdinal = is64 ? v >= ordinalFlag : (v & 0x80000000) !== 0;
    let name = '';
    let hint: number | undefined;
    let ordinal: number | undefined;
    if (byOrdinal) {
      ordinal = v & 0xffff;
      name = `Ordinal #${ordinal}`;
    } else {
      const ibnOff = rvaToOffset(v & 0x7fffffff);
      if (ibnOff >= 0 && r.canRead(2, ibnOff)) {
        hint = r.u16(ibnOff);
        name = r.cstr(ibnOff + 2, 512);
      } else {
        name = `<unresolved ${hex(v)}>`;
      }
    }
    let boundValue: number | undefined;
    if (iatBase >= 0 && r.canRead(step, iatBase + i * step)) {
      const bv = is64 ? r.u64(iatBase + i * step) : r.u32(iatBase + i * step);
      if (bv !== v) boundValue = bv;
    }
    out.push({
      name,
      ordinal,
      hint,
      byOrdinal,
      iatRva: iatRva + i * step,
      boundValue,
      category: categorizeApi(name, dll),
    });
  }
  return out;
}

const API_GROUPS: { re: RegExp; label: string }[] = [
  { re: /^(CreateFile|ReadFile|WriteFile|DeleteFile|MoveFile|CopyFile|FindFirstFile|FindNextFile|GetFileAttr|SetFilePointer|CloseHandle|CreateDirectory|GetTempPath|GetFullPathName|SetEndOfFile|FlushFileBuffers)/i, label: 'File I/O' },
  { re: /^(RegOpen|RegCreate|RegQuery|RegSet|RegClose|RegDelete|RegEnum)/i, label: 'Registry' },
  { re: /^(socket|connect|send|recv|bind|listen|accept|WSA|getaddrinfo|InternetOpen|HttpSend|WinHttp|URLDownload|closesocket|gethostby)/i, label: 'Network' },
  { re: /^(CreateProcess|CreateThread|CreateRemoteThread|OpenProcess|TerminateProcess|ExitProcess|ShellExecute|WinExec|Sleep|WaitForSingleObject|WaitForMultiple|ResumeThread|SuspendThread|GetCurrentProcess|GetCurrentThread)/i, label: 'Process & Threads' },
  { re: /^(VirtualAlloc|VirtualProtect|VirtualFree|VirtualQuery|HeapAlloc|HeapFree|HeapCreate|GlobalAlloc|LocalAlloc|MapViewOfFile|CreateFileMapping|malloc|free|new|delete)/i, label: 'Memory' },
  { re: /^(LoadLibrary|GetProcAddress|FreeLibrary|GetModuleHandle|GetModuleFileName|DisableThreadLibraryCalls)/i, label: 'Dynamic Loading' },
  { re: /^(Crypt|Bcrypt|Ncrypt|CertOpen|CertFind|CertGet|RtlGenRandom|SystemFunction036|MD5|SHA)/i, label: 'Cryptography' },
  { re: /^(OpenSCManager|CreateService|StartService|ControlService|RegisterServiceCtrl|SetServiceStatus)/i, label: 'Services' },
  { re: /^(AdjustTokenPrivileges|OpenProcessToken|LookupPrivilege|ImpersonateLoggedOnUser|LogonUser|DuplicateToken|CheckTokenMembership|GetUserName)/i, label: 'Security & Tokens' },
  { re: /^(CreateWindow|ShowWindow|MessageBox|DefWindowProc|RegisterClass|GetMessage|DispatchMessage|SetWindowPos|InvalidateRect|BeginPaint)/i, label: 'UI & Windowing' },
  { re: /^(CoInitialize|CoCreateInstance|CoTaskMem|SysAllocString|VariantInit|IID_|CLSID_|OleInitialize)/i, label: 'COM & OLE' },
  { re: /^(_|\?\?|std@@|memcpy|memset|strlen|strcpy|sprintf|printf|wcs|mbs|qsort|atoi|_amsg|__C_specific)/, label: 'C/C++ Runtime' },
  { re: /^(Etw|Trace|EventRegister|EventWrite|EventActivity|TraceMessage|McGenEventRegister)/i, label: 'ETW & Tracing' },
  { re: /^(Nt|Zw)[A-Z]/, label: 'NT Native API' },
  { re: /^Rtl[A-Z]/, label: 'RTL Runtime Library' },
  { re: /^(Ldr)[A-Z]/, label: 'Loader Internals' },
  { re: /^(InitializeCriticalSection|EnterCriticalSection|LeaveCriticalSection|DeleteCriticalSection|Interlocked|CreateEvent|SetEvent|ResetEvent|CreateMutex|ReleaseMutex|CreateSemaphore|InitOnce|SRWLock|ConditionVariable|Sleep(Ex|ConditionVariable))/i, label: 'Synchronisation' },
  { re: /^(Get|Set)(Environment|CommandLine|SystemDirectory|WindowsDirectory|ComputerName|LocaleInfo|VersionEx|SystemInfo|NativeSystemInfo)/i, label: 'Environment & System Info' },
  { re: /^(MultiByteToWideChar|WideCharToMultiByte|CompareString|LCMapString|GetStringType|IsCharAlpha|CharUpper|CharLower|lstr)/i, label: 'Text & Locale' },
  { re: /^(GetLastError|SetLastError|FormatMessage|OutputDebugString|RaiseException|IsDebuggerPresent|SetUnhandledException|GetSystemTime|QueryPerformance|GetTickCount|DebugBreak)/i, label: 'Diagnostics & Time' },
];

function categorizeApi(name: string, _dll: string) {
  for (const g of API_GROUPS) if (g.re.test(name)) return g.label;
  return 'Other';
}

const DLL_GROUPS: { re: RegExp; label: string }[] = [
  { re: /^(kernel32|kernelbase|ntdll|api-ms-win-core)/i, label: 'Core OS' },
  { re: /^(user32|gdi32|comctl32|comdlg32|shell32|uxtheme|dwmapi|d2d1|d3d|dxgi|windowscodecs)/i, label: 'UI & Graphics' },
  { re: /^(advapi32|secur32|crypt32|bcrypt|ncrypt|wintrust|sechost)/i, label: 'Security & Crypto' },
  { re: /^(ws2_32|wininet|winhttp|urlmon|dnsapi|iphlpapi|mswsock|netapi32)/i, label: 'Networking' },
  { re: /^(ole32|oleaut32|combase|propsys|shlwapi)/i, label: 'COM & Shell' },
  { re: /^(msvcp|msvcr|vcruntime|ucrtbase|api-ms-win-crt|concrt)/i, label: 'C/C++ Runtime' },
  { re: /^(mscoree|clr|mscorlib)/i, label: '.NET Runtime' },
];

function categorizeDll(dll: string) {
  for (const g of DLL_GROUPS) if (g.re.test(dll)) return g.label;
  return 'Other';
}

function formatGuid(r: Reader, at: number) {
  const d1 = r.u32(at).toString(16).padStart(8, '0');
  const d2 = r.u16(at + 4).toString(16).padStart(4, '0');
  const d3 = r.u16(at + 6).toString(16).padStart(4, '0');
  let rest = '';
  for (let i = 0; i < 8; i++) rest += r.u8(at + 8 + i).toString(16).padStart(2, '0');
  return `${d1}-${d2}-${d3}-${rest.slice(0, 4)}-${rest.slice(4)}`.toUpperCase();
}

function readResourceDir(
  r: Reader,
  base: number,
  at: number,
  level: number,
  rvaToOffset: (rva: number) => number,
  counter: { n: number },
  idOrName: number | string = 'Root',
  typeName?: string,
): ResourceNode {
  const node: ResourceNode = {
    id: idOrName,
    name: typeof idOrName === 'string' ? idOrName : String(idOrName),
    typeName,
    level,
    children: [],
  };
  if (!r.canRead(16, at) || level > 4) return node;
  const namedCount = r.u16(at + 12);
  const idCount = r.u16(at + 14);
  const total = Math.min(namedCount + idCount, 8192);
  for (let i = 0; i < total; i++) {
    const eAt = at + 16 + i * 8;
    if (!r.canRead(8, eAt)) break;
    const nameField = r.u32(eAt);
    const offsetField = r.u32(eAt + 4);
    let entryId: number | string;
    if (nameField & 0x80000000) {
      const nameOff = base + (nameField & 0x7fffffff);
      const len = r.canRead(2, nameOff) ? r.u16(nameOff) : 0;
      entryId = r.wstr(nameOff + 2, Math.min(len, 256));
    } else {
      entryId = nameField;
    }
    const childTypeName =
      level === 0 && typeof entryId === 'number' ? RESOURCE_TYPE[entryId] : undefined;
    if (offsetField & 0x80000000) {
      node.children!.push(
        readResourceDir(r, base, base + (offsetField & 0x7fffffff), level + 1, rvaToOffset, counter, entryId, childTypeName),
      );
    } else {
      const dAt = base + offsetField;
      if (!r.canRead(16, dAt)) continue;
      const dataRva = r.u32(dAt);
      const dataSize = r.u32(dAt + 4);
      const codePage = r.u32(dAt + 8);
      counter.n++;
      const fo = rvaToOffset(dataRva);
      node.children!.push({
        id: entryId,
        name: String(entryId),
        typeName: childTypeName,
        level: level + 1,
        dataRva,
        dataSize,
        codePage,
        fileOffset: fo,
      });
    }
  }
  return node;
}

function extractVersionInfo(
  r: Reader,
  root: ResourceNode,
  _rvaToOffset: (rva: number) => number,
): Record<string, string> | undefined {
  const verNode = root.children?.find((c) => c.id === 16);
  if (!verNode) return undefined;
  let leaf: ResourceNode | undefined;
  const walk = (n: ResourceNode) => {
    if (n.fileOffset !== undefined && n.dataSize) {
      leaf = leaf ?? n;
      return;
    }
    n.children?.forEach(walk);
  };
  walk(verNode);
  if (!leaf || leaf.fileOffset === undefined || leaf.fileOffset < 0) return undefined;

  const start = leaf.fileOffset;
  const end = Math.min(start + (leaf.dataSize ?? 0), r.length);
  const out: Record<string, string> = {};

  // Fixed file info: locate the VS_FIXEDFILEINFO signature.
  for (let p = start; p + 4 < end; p += 4) {
    if (r.u32(p) === 0xfeef04bd) {
      const fileVerMs = r.u32(p + 8);
      const fileVerLs = r.u32(p + 12);
      const prodVerMs = r.u32(p + 16);
      const prodVerLs = r.u32(p + 20);
      out['FileVersion (binary)'] = `${fileVerMs >>> 16}.${fileVerMs & 0xffff}.${fileVerLs >>> 16}.${fileVerLs & 0xffff}`;
      out['ProductVersion (binary)'] = `${prodVerMs >>> 16}.${prodVerMs & 0xffff}.${prodVerLs >>> 16}.${prodVerLs & 0xffff}`;
      break;
    }
  }

  // StringFileInfo key/value pairs: scan for UTF-16 pairs.
  const wanted = [
    'CompanyName',
    'FileDescription',
    'FileVersion',
    'InternalName',
    'LegalCopyright',
    'OriginalFilename',
    'ProductName',
    'ProductVersion',
    'Comments',
  ];
  let p = start;
  while (p + 6 < end) {
    const wLength = r.u16(p);
    const wValueLength = r.u16(p + 2);
    const wType = r.u16(p + 4);
    if (wLength < 6 || p + wLength > end) {
      p += 2;
      continue;
    }
    const key = r.wstr(p + 6, 128);
    if (wType === 1 && wValueLength > 0 && wanted.includes(key)) {
      let vp = p + 6 + (key.length + 1) * 2;
      vp = (vp + 3) & ~3;
      const val = r.wstr(vp, wValueLength + 1);
      if (val) out[key] = val;
    }
    p += (wLength + 3) & ~3;
    if (wLength === 0) break;
  }
  return Object.keys(out).length ? out : undefined;
}

function parseRich(r: Reader, peOffset: number): RichHeader | undefined {
  // Search backwards from the PE header for the 'Rich' marker.
  let richOff = -1;
  for (let p = peOffset - 4; p >= 0x40; p -= 4) {
    if (!r.canRead(4, p)) continue;
    if (r.u32(p) === 0x68636952) {
      richOff = p;
      break;
    }
  }
  if (richOff < 0) return undefined;
  const key = r.u32(richOff + 4);
  // Walk back to the 'DanS' marker (XORed with the key).
  let start = -1;
  for (let p = richOff - 4; p >= 0x40; p -= 4) {
    if ((r.u32(p) ^ key) === 0x536e6144) {
      start = p;
      break;
    }
  }
  if (start < 0) return undefined;
  const entries: RichHeader['entries'] = [];
  for (let p = start + 16; p + 8 <= richOff; p += 8) {
    const idVer = r.u32(p) ^ key;
    const count = r.u32(p + 4) ^ key;
    const productId = idVer >>> 16;
    const buildNumber = idVer & 0xffff;
    if (!idVer && !count) continue;
    entries.push({
      productId,
      productName: RICH_PRODUCT[productId] ?? `Product 0x${productId.toString(16)}`,
      buildNumber,
      count,
    });
  }
  return { offset: start, size: richOff + 8 - start, key, entries, checksumValid: true };
}

function buildMemoryRegions(
  sections: PESection[],
  sizeOfHeaders: number,
  sizeOfImage: number,
  sectionAlignment: number,
  dirs: PEImage['dataDirectories'],
): MemoryRegion[] {
  const regions: MemoryRegion[] = [];
  const align = (n: number) => (sectionAlignment ? Math.ceil(n / sectionAlignment) * sectionAlignment : n);

  regions.push({
    id: 'hdr',
    label: 'PE Headers',
    kind: 'headers',
    start: 0,
    size: align(sizeOfHeaders) || sizeOfHeaders,
    color: '#8b8fa3',
    detail: 'DOS header, PE signature, COFF + optional headers and the section table. Mapped read-only at the image base.',
  });

  const sorted = [...sections].sort((a, b) => a.virtualAddress - b.virtualAddress);
  let cursor = align(sizeOfHeaders);
  sorted.forEach((s) => {
    if (s.virtualAddress > cursor) {
      regions.push({
        id: `gap-${s.index}`,
        label: 'Alignment gap',
        kind: 'gap',
        start: cursor,
        size: s.virtualAddress - cursor,
        color: '#1b1d2a',
        detail: 'Unmapped padding between sections created by SectionAlignment rounding.',
      });
    }
    const vsize = align(s.virtualSize || s.rawSize);
    regions.push({
      id: `sec-${s.index}`,
      label: s.name,
      kind: 'section',
      start: s.virtualAddress,
      size: vsize,
      color: colorForSection(s),
      sectionIndex: s.index,
      detail: s.desc,
    });
    cursor = s.virtualAddress + vsize;
  });
  if (cursor < sizeOfImage) {
    regions.push({
      id: 'tail',
      label: 'Reserved tail',
      kind: 'gap',
      start: cursor,
      size: sizeOfImage - cursor,
      color: '#1b1d2a',
      detail: 'Address space reserved by SizeOfImage but not covered by any section.',
    });
  }

  dirs.forEach((d) => {
    if (!d.rva || !d.size || d.index === 4) return; // certificate table is a file offset
    const parent = sorted.find(
      (s) => d.rva >= s.virtualAddress && d.rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize),
    );
    regions.push({
      id: `dir-${d.index}`,
      label: d.name,
      kind: 'directory',
      start: d.rva,
      size: d.size,
      color: DIRECTORY_COLOR[d.index] ?? '#7aa2f7',
      parentId: parent ? `sec-${parent.index}` : 'hdr',
      detail: d.desc,
    });
  });

  return regions;
}

function buildFileRegions(
  sections: PESection[],
  sizeOfHeaders: number,
  fileSize: number,
  certDir: { rva: number; size: number },
): MemoryRegion[] {
  const regions: MemoryRegion[] = [];
  regions.push({
    id: 'fhdr',
    label: 'Headers',
    kind: 'headers',
    start: 0,
    size: sizeOfHeaders,
    color: '#8b8fa3',
    detail: 'All headers as stored on disk.',
  });
  const sorted = [...sections].filter((s) => s.rawSize > 0).sort((a, b) => a.rawPointer - b.rawPointer);
  let cursor = sizeOfHeaders;
  sorted.forEach((s) => {
    if (s.rawPointer > cursor) {
      regions.push({
        id: `fgap-${s.index}`,
        label: 'File padding',
        kind: 'gap',
        start: cursor,
        size: s.rawPointer - cursor,
        color: '#1b1d2a',
        detail: 'Zero padding inserted to satisfy FileAlignment.',
      });
    }
    regions.push({
      id: `fsec-${s.index}`,
      label: s.name,
      kind: 'section',
      start: s.rawPointer,
      size: s.rawSize,
      color: colorForSection(s),
      sectionIndex: s.index,
      detail: `${s.desc} On disk this occupies ${formatSize(s.rawSize)}.`,
    });
    cursor = Math.max(cursor, s.rawPointer + s.rawSize);
  });
  if (certDir.rva && certDir.size) {
    regions.push({
      id: 'fcert',
      label: 'Authenticode signature',
      kind: 'overlay',
      start: certDir.rva,
      size: certDir.size,
      color: '#d4a5ff',
      detail: 'The PKCS#7 signature blob. It lives past the last section and is never mapped into memory.',
    });
    cursor = Math.max(cursor, certDir.rva + certDir.size);
  }
  if (cursor < fileSize) {
    regions.push({
      id: 'foverlay',
      label: 'Overlay',
      kind: 'overlay',
      start: cursor,
      size: fileSize - cursor,
      color: '#ffb86c',
      detail: 'Extra data appended after the last section. Installers, packers and self-extracting archives stash payloads here — it is never loaded into memory.',
    });
  }
  return regions;
}

export { SECTION_COLORS };
