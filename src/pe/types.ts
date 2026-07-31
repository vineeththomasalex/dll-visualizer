export interface Field {
  name: string;
  /** Absolute file offset of this field. */
  offset: number;
  size: number;
  value: string;
  raw?: number;
  desc?: string;
  /** Optional decoded flag list. */
  flags?: { name: string; desc: string; set: boolean }[];
  warn?: string;
}

export interface FieldGroup {
  id: string;
  title: string;
  offset: number;
  size: number;
  desc: string;
  fields: Field[];
}

export interface PESection {
  index: number;
  name: string;
  virtualAddress: number;
  virtualSize: number;
  rawPointer: number;
  rawSize: number;
  characteristics: number;
  flagNames: string[];
  perms: string;
  entropy: number;
  /** Per-chunk entropy for the heat strip. */
  entropyMap: number[];
  relocPointer: number;
  numberOfRelocations: number;
  desc: string;
  slack: number;
}

export interface ImportSymbol {
  name: string;
  ordinal?: number;
  hint?: number;
  byOrdinal: boolean;
  iatRva: number;
  /** Bound address already written in the IAT, if present. */
  boundValue?: number;
  category: string;
}

export interface ImportModule {
  dll: string;
  descriptorRva: number;
  originalFirstThunk: number;
  firstThunk: number;
  timeDateStamp: number;
  forwarderChain: number;
  symbols: ImportSymbol[];
  delayLoaded: boolean;
  category: string;
}

export interface ExportSymbol {
  name?: string;
  ordinal: number;
  rva: number;
  forwarder?: string;
  nameRva?: number;
  section?: string;
}

export interface ExportInfo {
  dllName: string;
  timeDateStamp: number;
  ordinalBase: number;
  numberOfFunctions: number;
  numberOfNames: number;
  addressTableRva: number;
  namePointerRva: number;
  ordinalTableRva: number;
  symbols: ExportSymbol[];
}

export interface RelocBlock {
  pageRva: number;
  sizeOfBlock: number;
  entries: { type: number; typeName: string; offset: number; rva: number }[];
}

export interface ResourceNode {
  id: number | string;
  name: string;
  typeName?: string;
  level: number;
  children?: ResourceNode[];
  dataRva?: number;
  dataSize?: number;
  codePage?: number;
  fileOffset?: number;
  preview?: string;
}

export interface DebugEntry {
  type: number;
  typeName: string;
  timeDateStamp: number;
  sizeOfData: number;
  addressOfRawData: number;
  pointerToRawData: number;
  /** CodeView specific */
  pdbPath?: string;
  guid?: string;
  age?: number;
  signature?: string;
}

export interface MemoryRegion {
  id: string;
  label: string;
  kind:
    | 'headers'
    | 'section'
    | 'gap'
    | 'overlay'
    | 'directory'
    | 'sectionSlack';
  /** RVA-space start (virtual). For file-space regions this is the file offset. */
  start: number;
  size: number;
  color: string;
  sectionIndex?: number;
  detail?: string;
  /** Sub-regions painted on top of a section band. */
  parentId?: string;
}

export interface CLRInfo {
  cb: number;
  runtimeVersion: string;
  metadataRva: number;
  metadataSize: number;
  flags: number;
  flagNames: string[];
  entryPointToken: number;
  metadataVersion?: string;
  streams?: { name: string; offset: number; size: number }[];
}

export interface TLSInfo {
  startAddressOfRawData: number;
  endAddressOfRawData: number;
  addressOfIndex: number;
  addressOfCallbacks: number;
  sizeOfZeroFill: number;
  characteristics: number;
  callbacks: number[];
}

export interface RichEntry {
  productId: number;
  productName: string;
  buildNumber: number;
  count: number;
}

export interface RichHeader {
  offset: number;
  size: number;
  key: number;
  entries: RichEntry[];
  checksumValid: boolean;
}

export interface PEImage {
  fileName: string;
  fileSize: number;
  bytes: Uint8Array;
  is64: boolean;
  isDll: boolean;
  machine: number;
  machineName: string;
  peOffset: number;
  imageBase: number;
  entryPoint: number;
  sizeOfImage: number;
  sizeOfHeaders: number;
  sectionAlignment: number;
  fileAlignment: number;
  subsystem: number;
  subsystemName: string;
  timeDateStamp: number;
  checksum: number;
  computedChecksum: number;
  groups: FieldGroup[];
  dataDirectories: {
    index: number;
    name: string;
    rva: number;
    size: number;
    desc: string;
  }[];
  sections: PESection[];
  imports: ImportModule[];
  exports?: ExportInfo;
  relocations: RelocBlock[];
  relocCount: number;
  resources?: ResourceNode;
  resourceCount: number;
  debug: DebugEntry[];
  tls?: TLSInfo;
  clr?: CLRInfo;
  loadConfig?: Field[];
  rich?: RichHeader;
  certificates: { offset: number; size: number; revision: number; type: string }[];
  memoryRegions: MemoryRegion[];
  fileRegions: MemoryRegion[];
  characteristics: number;
  characteristicFlags: { name: string; desc: string; set: boolean }[];
  dllCharacteristics: number;
  dllCharacteristicFlags: { name: string; desc: string; set: boolean }[];
  warnings: string[];
  entropy: number;
  versionInfo?: Record<string, string>;
  hasCFG: boolean;
  hasASLR: boolean;
  hasDEP: boolean;
  hasSEH: boolean;
  hasAuthenticode: boolean;
  isDotNet: boolean;
}
