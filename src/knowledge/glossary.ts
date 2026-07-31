export interface Topic {
  id: string;
  title: string;
  body: string;
  bullets?: string[];
  seeAlso?: string[];
}

const SECTION_DESCRIPTIONS: { match: RegExp; desc: string }[] = [
  { match: /^\.text/i, desc: 'Executable machine code. Mapped read + execute, never writable, so the CPU can run it while DEP blocks any attempt to modify it.' },
  { match: /^\.rdata/i, desc: 'Read-only initialized data: string literals, vtables, const arrays, and the import/export descriptors. Mapped read-only.' },
  { match: /^\.data/i, desc: 'Writable initialized globals. Each process gets a private copy-on-write view, so writing here does not affect other processes.' },
  { match: /^\.bss/i, desc: 'Uninitialized globals. Occupies address space but no file bytes — the loader simply hands out zero pages.' },
  { match: /^\.rsrc/i, desc: 'The resource tree: icons, dialogs, string tables, version info, and the side-by-side manifest.' },
  { match: /^\.reloc/i, desc: 'Base relocations. If ASLR moves the image away from its preferred base, the loader walks this list and patches every hard-coded address. Marked discardable.' },
  { match: /^\.pdata/i, desc: 'Exception unwind tables (RUNTIME_FUNCTION records). On x64 and ARM64 stack unwinding is table-driven, so there is no per-function prologue cost.' },
  { match: /^\.xdata/i, desc: 'The unwind opcode blobs that .pdata entries point at — they describe how to undo a function prologue.' },
  { match: /^\.tls/i, desc: 'Thread Local Storage template. Copied for every new thread so each gets its own __declspec(thread) variables.' },
  { match: /^\.idata/i, desc: 'Import directory data. Modern linkers usually fold this into .rdata instead.' },
  { match: /^\.edata/i, desc: 'Export directory data. Modern linkers usually fold this into .rdata instead.' },
  { match: /^\.didat/i, desc: 'Delay-load import data — descriptors for DLLs resolved on first use rather than at load time.' },
  { match: /^\.gfids/i, desc: 'Control Flow Guard function-ID table: the set of addresses that are valid indirect-call targets.' },
  { match: /^\.CRT/i, desc: 'C runtime initializer/terminator function pointer arrays, walked before main / DllMain.' },
  { match: /^\.debug/i, desc: 'Embedded debug information. Usually stripped into a separate PDB instead.' },
  { match: /^\.sxdata/i, desc: 'SafeSEH data: the list of legal 32-bit exception handlers.' },
  { match: /^UPX|^\.upx/i, desc: 'A UPX packer section — the real code is compressed and unpacked into memory at runtime.' },
  { match: /^\.themida|^\.vmp|^\.enigma|^\.aspack/i, desc: 'A commercial packer/protector section. Contents are encrypted or virtualized until runtime.' },
  { match: /^\.textbss/i, desc: 'Incremental-linking thunk padding produced by debug builds.' },
  { match: /^\.msvcjmc/i, desc: 'MSVC "Just My Code" instrumentation data used by the debugger to skip library frames.' },
  { match: /^\.00cfg/i, desc: 'Control Flow Guard configuration data emitted by MSVC.' },
  { match: /^\.detourc|^\.detourd/i, desc: 'Microsoft Detours payload sections, used to store hook metadata inside an instrumented image.' },
];

export function describeSection(name: string): string {
  for (const s of SECTION_DESCRIPTIONS) if (s.match.test(name)) return s.desc;
  return 'A custom section. Its meaning is defined by whatever produced the image — check the characteristics flags to see how it is mapped.';
}

export const TOPICS: Record<string, Topic> = {
  overview: {
    id: 'overview',
    title: 'What am I looking at?',
    body: 'A DLL is a file on disk *and* a layout in memory, and the two are not the same shape. The map on the left shows the virtual layout: exactly the bytes the Windows loader will hand your process, in address order starting at the image base.',
    bullets: [
      'Every band is a section — a run of pages that share one set of permissions.',
      'Thin bright stripes are data directories: tables the loader looks up by index.',
      'Switch to File Layout to see how the same content is packed on disk, including the parts (signature, overlay) that never get mapped.',
      'Click anything to pin its details here.',
    ],
  },
  rva: {
    id: 'rva',
    title: 'RVA vs File Offset vs VA',
    body: 'Three different address spaces are in play, and mixing them up is the number one source of PE confusion.',
    bullets: [
      'RVA (Relative Virtual Address): an offset from the image base, once loaded. Almost every field in a PE header is an RVA.',
      'File Offset: where the byte physically sits in the file. Differs from the RVA because sections are aligned to 512 bytes on disk but 4096 in memory.',
      'VA (Virtual Address): image base + RVA. The actual pointer value a running process sees.',
      'The Certificate Table is the one directory that stores a *file offset* instead of an RVA — because signatures are never mapped.',
    ],
  },
  loader: {
    id: 'loader',
    title: 'How the loader maps this',
    body: 'When something calls LoadLibrary, the loader performs a fixed sequence of steps using the tables shown here.',
    bullets: [
      'Reserve SizeOfImage bytes of address space, preferring ImageBase but relocating anywhere if ASLR is on.',
      'Map the headers, then map each section at its RVA with the protection implied by its characteristics.',
      'If the base moved, walk the .reloc table and patch every listed address by the delta.',
      'Walk the import table: load each dependency and write real function addresses into the IAT.',
      'Run TLS callbacks, then call DllMain with DLL_PROCESS_ATTACH.',
    ],
  },
  headers: {
    id: 'headers',
    title: 'PE Headers',
    body: 'The first few hundred bytes are pure metadata: a DOS relic, an optional Rich provenance blob, the COFF header, the optional header, and the section table. They are mapped read-only at the image base, which is why you can read a module\u2019s own headers at runtime.',
    seeAlso: ['rva'],
  },
  imports: {
    id: 'imports',
    title: 'Imports and the IAT',
    body: 'Imports are the module\u2019s dependency list. For each DLL there are two parallel arrays of thunks: the Import Name Table (names, stays constant) and the Import Address Table (patched by the loader with real function pointers).',
    bullets: [
      'A call to an imported function compiles to an indirect call through its IAT slot.',
      'The IAT lives in writable memory precisely so the loader can patch it — which is also why IAT hooking is so easy.',
      'Delay-loaded imports skip all of this until the first call, then a helper stub resolves them on demand.',
      'Ordinal-only imports have no name; they are matched purely by index, which is fragile across versions.',
    ],
  },
  exports: {
    id: 'exports',
    title: 'Exports',
    body: 'The export table is the public API surface. It is really three parallel arrays: function RVAs indexed by ordinal, a sorted array of name pointers, and an ordinal index that maps names back to slots.',
    bullets: [
      'GetProcAddress binary-searches the sorted name array — that is why exports must be sorted.',
      'If an export\u2019s RVA points back inside the export directory it is a *forwarder*: a string like "NTDLL.RtlAllocHeap" redirecting the caller elsewhere.',
      'Ordinals are stable contract numbers; exporting by ordinal only is how some system DLLs hide private APIs.',
    ],
  },
  relocs: {
    id: 'relocs',
    title: 'Base Relocations',
    body: 'Compiled code sometimes embeds absolute addresses. If the loader cannot place the image at its preferred base, every one of those must be adjusted by the same delta. The .reloc section is the list of where they are.',
    bullets: [
      'Entries are grouped into 4 KB page blocks so the fixups are cache friendly.',
      'Each entry is 16 bits: 4 bits of type, 12 bits of offset within the page.',
      'Type 3 (HIGHLOW) is the 32-bit fixup; type 10 (DIR64) is the 64-bit one; type 0 is padding.',
      'No .reloc means no ASLR — the image must load at its preferred base or fail.',
    ],
  },
  resources: {
    id: 'resources',
    title: 'Resources',
    body: 'A three-level tree — type, then name/ID, then language — ending in leaves that point at raw blobs. This is where icons, dialog templates, string tables, version info, and the application manifest live.',
    bullets: [
      'Resource-only DLLs (satellite assemblies) contain nothing but this tree and no entry point at all.',
      'The MANIFEST resource controls UAC elevation, DPI awareness, and side-by-side assembly binding.',
      'The VERSION resource is what File Explorer reads for the Details tab.',
    ],
  },
  security: {
    id: 'security',
    title: 'Exploit mitigations',
    body: 'The DllCharacteristics field plus the load config directory record which hardening features the image opted into. Missing ones are genuine risk, not cosmetics.',
    bullets: [
      'ASLR (DYNAMIC_BASE) randomizes the load address so exploit payloads cannot hard-code addresses.',
      'DEP (NX_COMPAT) makes data pages non-executable, defeating classic shellcode injection.',
      'CFG (GUARD_CF) validates every indirect call against a bitmap of legal targets.',
      'SafeSEH / NO_SEH restrict which exception handlers may run, blocking SEH overwrite attacks.',
      'A section that is writable AND executable defeats all of the above and almost always means a packer.',
    ],
  },
  entropy: {
    id: 'entropy',
    title: 'Entropy',
    body: 'Shannon entropy measures how unpredictable the bytes are, from 0 (all one value) to 8 (perfectly random). It is a fast way to spot compression and encryption.',
    bullets: [
      'Normal x86/x64 code sits around 6.0\u20136.5.',
      'English strings and tables sit around 3\u20135.',
      'Above ~7.2 across a whole section means compressed, encrypted, or already-compressed media.',
      'A near-zero band is padding or a zero-filled table.',
    ],
  },
  tls: {
    id: 'tls',
    title: 'Thread Local Storage',
    body: 'The TLS directory stores a template of initial values plus an array of callbacks. Every time a thread attaches, Windows copies the template and runs the callbacks — before DllMain in the process-attach case.',
    bullets: [
      'TLS callbacks run earlier than any other user code in the module, which is why malware loves them for anti-debug checks.',
      'AddressOfIndex points at the slot where the loader stores this module\u2019s TLS index.',
    ],
  },
  debug: {
    id: 'debug',
    title: 'Debug directory & PDBs',
    body: 'The CodeView debug entry names the PDB that matches this exact build, together with a GUID and an age counter. A debugger will only accept a PDB whose GUID and age match byte for byte.',
    bullets: [
      'Load the matching .pdb here to see real function names on top of the layout.',
      'A REPRO entry means the build is deterministic and the TimeDateStamp is a content hash, not a date.',
      'POGO entries mean profile-guided optimization reordered the hot code.',
    ],
  },
  dotnet: {
    id: 'dotnet',
    title: '.NET assemblies',
    body: 'A managed DLL is still a PE, but almost all of its content is CLI metadata and IL rather than native code. The COR20 header points at the metadata root, which contains the #~ table stream, the #Strings heap, and friends.',
    bullets: [
      'The native entry point is vestigial — the CLR takes over via mscoree.',
      'ILONLY means there is no native code at all, so the same file runs on any architecture.',
    ],
  },
  compare: {
    id: 'compare',
    title: 'Comparing two builds',
    body: 'Two versions of the same module are rarely different everywhere. The comparison pins down exactly what moved: the layout, the content of each section, the dependency list, the exported API, the resources, and the security flags.',
    bullets: [
      'Both images are drawn to one shared byte scale, so a taller column really is a bigger image.',
      'Matched sections are joined by ribbons — a slope means everything after that point shifted address.',
      'Similarity compares each matched section in 512-byte blocks, so you can tell a targeted patch from a full rebuild.',
      'A removed export is a hard breaking change; a changed ordinal is a silent one.',
      'Mitigations that were switched off between builds are flagged as a regression.',
      'The PDB GUID always differs between builds — it identifies one exact image, not a version.',
    ],
    seeAlso: ['security', 'exports'],
  },
  overlay: {
    id: 'overlay',
    title: 'Overlay data',
    body: 'Anything appended after the last section is an overlay. The loader never maps it, so it is free storage: installers, self-extracting archives, and licence blobs all hide payloads there.',
  },
  rich: {
    id: 'rich',
    title: 'The Rich header',
    body: 'An undocumented Microsoft blob squeezed between the DOS stub and the PE signature, XOR-encrypted with a checksum key. It records which compiler and linker builds produced each object file that went into the image — accidental but excellent build provenance.',
  },
  disasm: {
    id: 'disasm',
    title: 'Disassembly',
    body: 'Bytes from the executable sections are decoded with Capstone compiled to WebAssembly, entirely inside your browser. Nothing is uploaded anywhere.',
    bullets: [
      'Start points are seeded from the entry point, exports, and any symbols you loaded.',
      'Call and jump targets are annotated with matching export or PDB names where possible.',
    ],
  },
  symbols: {
    id: 'symbols',
    title: 'Symbols (PDB / MAP)',
    body: 'Drop the matching PDB or linker .map file in and the addresses here get real names. The PDB reader parses the MSF container and the public symbol stream directly in the browser.',
    bullets: [
      'A PDB only matches if its GUID and age equal the ones in the debug directory — the app checks this for you.',
      'MAP files are plain text and always readable, but only contain public symbols.',
    ],
  },
};

export const SECTION_TOPIC_HINTS: { match: RegExp; topic: string }[] = [
  { match: /^\.text/i, topic: 'disasm' },
  { match: /^\.reloc/i, topic: 'relocs' },
  { match: /^\.rsrc/i, topic: 'resources' },
  { match: /^\.tls/i, topic: 'tls' },
  { match: /^\.rdata/i, topic: 'imports' },
];

export const TIPS: string[] = [
  'Everything runs locally. Your DLL never leaves the browser.',
  'Hover any band in the map for a live readout; click to pin it.',
  'Toggle Virtual vs File layout to see how alignment padding inflates the image.',
  'The highlight filters recolour the map by permission, entropy, or directory.',
  'Drop the matching PDB alongside the DLL to name the addresses.',
  'A writable + executable section is almost always a packer.',
  'Press / to jump to search in any table.',
];
