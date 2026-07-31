import type { ExportSymbol, PEImage, PESection, ResourceNode } from './types';
import { formatSize, hexBig } from './reader';
import { DLL_CHARACTERISTICS } from './constants';

export type ChangeKind = 'same' | 'changed' | 'added' | 'removed';

export interface FieldDiff {
  name: string;
  a: string;
  b: string;
  changed: boolean;
  /** Signed byte delta when the field is a size. */
  delta?: number;
  note?: string;
}

export interface SectionDiff {
  name: string;
  kind: ChangeKind;
  a?: PESection;
  b?: PESection;
  virtualDelta: number;
  rawDelta: number;
  entropyDelta: number;
  movedVa: boolean;
  flagsChanged: boolean;
  permsChanged: boolean;
  /** Fraction of 512-byte blocks that are byte-identical between the two sections. */
  similarity: number | null;
}

export interface ImportDiff {
  dll: string;
  kind: ChangeKind;
  category: string;
  delayLoaded: boolean;
  added: string[];
  removed: string[];
  commonCount: number;
}

export interface ExportsDiff {
  added: ExportSymbol[];
  removed: ExportSymbol[];
  moved: { name: string; ordinal: number; aRva: number; bRva: number }[];
  ordinalChanged: { name: string; a: number; b: number }[];
  forwarderChanged: { name: string; a?: string; b?: string }[];
  unchanged: number;
}

export interface ResourceDiff {
  path: string;
  kind: ChangeKind;
  aSize?: number;
  bSize?: number;
}

export interface DirectoryDiff {
  index: number;
  name: string;
  aRva: number;
  aSize: number;
  bRva: number;
  bSize: number;
  kind: ChangeKind;
}

export interface PEDiff {
  a: PEImage;
  b: PEImage;
  identity: FieldDiff[];
  layout: FieldDiff[];
  build: FieldDiff[];
  versionInfo: FieldDiff[];
  mitigations: { name: string; desc: string; a: boolean; b: boolean }[];
  sections: SectionDiff[];
  directories: DirectoryDiff[];
  imports: ImportDiff[];
  exports: ExportsDiff;
  resources: ResourceDiff[];
  /** Overall fraction of matched section bytes that are byte-identical. */
  similarity: number;
  headline: string[];
  counts: {
    sectionsAdded: number;
    sectionsRemoved: number;
    sectionsChanged: number;
    modulesAdded: number;
    modulesRemoved: number;
    functionsAdded: number;
    functionsRemoved: number;
    exportsAdded: number;
    exportsRemoved: number;
    exportsMoved: number;
    resourcesAdded: number;
    resourcesRemoved: number;
    resourcesChanged: number;
    mitigationsChanged: number;
  };
}

const signed = (n: number) => (n > 0 ? `+${n}` : String(n));

export const signedSize = (n: number) => (n === 0 ? '±0' : (n > 0 ? '+' : '−') + formatSize(Math.abs(n)));

function fnv1a(data: Uint8Array, start: number, len: number) {
  let h = 0x811c9dc5;
  const end = Math.min(start + len, data.length);
  for (let i = start; i < end; i++) {
    h ^= data[i];
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** Block-aligned similarity between two section payloads. */
function sectionSimilarity(a: PEImage, sa: PESection, b: PEImage, sb: PESection, block = 512) {
  const lenA = Math.min(sa.rawSize, Math.max(0, a.bytes.length - sa.rawPointer));
  const lenB = Math.min(sb.rawSize, Math.max(0, b.bytes.length - sb.rawPointer));
  if (!lenA || !lenB) return null;
  const blocks = Math.ceil(Math.max(lenA, lenB) / block);
  if (!blocks) return null;
  let same = 0;
  for (let i = 0; i < blocks; i++) {
    const offA = sa.rawPointer + i * block;
    const offB = sb.rawPointer + i * block;
    const inA = i * block < lenA;
    const inB = i * block < lenB;
    if (!inA || !inB) continue;
    if (fnv1a(a.bytes, offA, block) === fnv1a(b.bytes, offB, block)) same++;
  }
  return same / blocks;
}

function pairSections(a: PEImage, b: PEImage): SectionDiff[] {
  const out: SectionDiff[] = [];
  const usedB = new Set<number>();

  for (const sa of a.sections) {
    const sb = b.sections.find((x, i) => !usedB.has(i) && x.name === sa.name);
    if (!sb) {
      out.push({
        name: sa.name,
        kind: 'removed',
        a: sa,
        virtualDelta: -sa.virtualSize,
        rawDelta: -sa.rawSize,
        entropyDelta: 0,
        movedVa: false,
        flagsChanged: false,
        permsChanged: false,
        similarity: null,
      });
      continue;
    }
    usedB.add(b.sections.indexOf(sb));
    const flagsChanged = sa.characteristics !== sb.characteristics;
    const virtualDelta = sb.virtualSize - sa.virtualSize;
    const rawDelta = sb.rawSize - sa.rawSize;
    const entropyDelta = sb.entropy - sa.entropy;
    const similarity = sectionSimilarity(a, sa, b, sb);
    const changed =
      virtualDelta !== 0 ||
      rawDelta !== 0 ||
      flagsChanged ||
      sa.virtualAddress !== sb.virtualAddress ||
      Math.abs(entropyDelta) > 0.0005 ||
      (similarity !== null && similarity < 1);
    out.push({
      name: sa.name,
      kind: changed ? 'changed' : 'same',
      a: sa,
      b: sb,
      virtualDelta,
      rawDelta,
      entropyDelta,
      movedVa: sa.virtualAddress !== sb.virtualAddress,
      flagsChanged,
      permsChanged: sa.perms !== sb.perms,
      similarity,
    });
  }

  b.sections.forEach((sb, i) => {
    if (usedB.has(i)) return;
    out.push({
      name: sb.name,
      kind: 'added',
      b: sb,
      virtualDelta: sb.virtualSize,
      rawDelta: sb.rawSize,
      entropyDelta: 0,
      movedVa: false,
      flagsChanged: false,
      permsChanged: false,
      similarity: null,
    });
  });

  return out.sort((x, y) => (x.a?.virtualAddress ?? x.b?.virtualAddress ?? 0) - (y.a?.virtualAddress ?? y.b?.virtualAddress ?? 0));
}

function flattenResources(root: ResourceNode | undefined) {
  const out = new Map<string, number>();
  if (!root) return out;
  const walk = (n: ResourceNode, path: string[]) => {
    const label = n.typeName ?? String(n.name);
    const next = n.level === 0 ? path : [...path, label];
    if (n.dataSize !== undefined) {
      out.set(next.join(' / ') || label, n.dataSize);
      return;
    }
    n.children?.forEach((c) => walk(c, next));
  };
  root.children?.forEach((c) => walk(c, []));
  return out;
}

export function diffPE(a: PEImage, b: PEImage): PEDiff {
  const f = (name: string, av: string, bv: string, note?: string, delta?: number): FieldDiff => ({
    name,
    a: av,
    b: bv,
    changed: av !== bv,
    note,
    delta,
  });

  const identity: FieldDiff[] = [
    f('File name', a.fileName, b.fileName),
    f('Type', a.is64 ? 'PE32+ (64-bit)' : 'PE32 (32-bit)', b.is64 ? 'PE32+ (64-bit)' : 'PE32 (32-bit)', 'Changing bitness is an ABI break — every consumer must be rebuilt.'),
    f('Machine', a.machineName, b.machineName),
    f('Subsystem', a.subsystemName, b.subsystemName),
    f('Kind', a.isDll ? 'DLL' : 'Executable', b.isDll ? 'DLL' : 'Executable'),
    f('Managed (.NET)', a.isDotNet ? 'yes' : 'no', b.isDotNet ? 'yes' : 'no'),
    f('Signed', a.hasAuthenticode ? 'yes' : 'no', b.hasAuthenticode ? 'yes' : 'no'),
  ];

  const layout: FieldDiff[] = [
    f('File size', formatSize(a.fileSize), formatSize(b.fileSize), undefined, b.fileSize - a.fileSize),
    f('Size of image', formatSize(a.sizeOfImage), formatSize(b.sizeOfImage), 'Address space the loader reserves.', b.sizeOfImage - a.sizeOfImage),
    f('Size of headers', formatSize(a.sizeOfHeaders), formatSize(b.sizeOfHeaders), undefined, b.sizeOfHeaders - a.sizeOfHeaders),
    f('Image base', hexBig(a.imageBase, a.is64 ? 12 : 8), hexBig(b.imageBase, b.is64 ? 12 : 8), 'Preferred load address before ASLR.'),
    f('Entry point', a.entryPoint ? hexBig(a.entryPoint) : 'none', b.entryPoint ? hexBig(b.entryPoint) : 'none', 'Moves whenever code before it changes size.'),
    f('Sections', String(a.sections.length), String(b.sections.length)),
    f('Section alignment', formatSize(a.sectionAlignment), formatSize(b.sectionAlignment)),
    f('File alignment', formatSize(a.fileAlignment), formatSize(b.fileAlignment)),
    f('Overall entropy', a.entropy.toFixed(3), b.entropy.toFixed(3), 'A jump towards 8 suggests new compressed or encrypted content.'),
    f('Relocations', a.relocCount.toLocaleString(), b.relocCount.toLocaleString(), undefined, b.relocCount - a.relocCount),
  ];

  const cvA = a.debug.find((d) => d.type === 2);
  const cvB = b.debug.find((d) => d.type === 2);
  const linker = (p: PEImage) =>
    p.groups.find((g) => g.id === 'optional')?.fields.find((x) => x.name === 'LinkerVersion')?.value ?? '—';
  const stamp = (p: PEImage) =>
    p.reproducibleBuild
      ? `${hexBig(p.timeDateStamp)} (deterministic hash)`
      : p.timeDateStamp
        ? new Date(p.timeDateStamp * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
        : 'not set';

  const build: FieldDiff[] = [
    f('Linker version', linker(a), linker(b), 'A different toolset can change codegen everywhere at once.'),
    f('Build stamp', stamp(a), stamp(b)),
    f('CheckSum', hexBig(a.checksum), hexBig(b.checksum)),
    f('PDB', cvA?.pdbPath?.split(/[\\/]/).pop() ?? '—', cvB?.pdbPath?.split(/[\\/]/).pop() ?? '—'),
    f('PDB GUID', cvA?.guid ?? '—', cvB?.guid ?? '—', 'Always differs between builds — it is what ties a PDB to one exact image.'),
    f('Rich header tools', String(a.rich?.entries.length ?? 0), String(b.rich?.entries.length ?? 0), 'Number of distinct compiler/linker builds that contributed object files.'),
    f('Debug records', String(a.debug.length), String(b.debug.length)),
  ];

  const versionKeys = [...new Set([...Object.keys(a.versionInfo ?? {}), ...Object.keys(b.versionInfo ?? {})])];
  const versionInfo: FieldDiff[] = versionKeys.map((k) =>
    f(k, a.versionInfo?.[k] ?? '—', b.versionInfo?.[k] ?? '—'),
  );

  const mitigations = DLL_CHARACTERISTICS.map((d) => ({
    name: d.name,
    desc: d.desc,
    a: (a.dllCharacteristics & d.bit) !== 0,
    b: (b.dllCharacteristics & d.bit) !== 0,
  }));

  const sections = pairSections(a, b);

  const directories: DirectoryDiff[] = [];
  for (let i = 0; i < 16; i++) {
    const da = a.dataDirectories[i];
    const db = b.dataDirectories[i];
    const aRva = da?.rva ?? 0;
    const aSize = da?.size ?? 0;
    const bRva = db?.rva ?? 0;
    const bSize = db?.size ?? 0;
    if (!aRva && !bRva && !aSize && !bSize) continue;
    const kind: ChangeKind =
      !aRva && bRva ? 'added' : aRva && !bRva ? 'removed' : aRva !== bRva || aSize !== bSize ? 'changed' : 'same';
    directories.push({ index: i, name: da?.name ?? db?.name ?? `Directory ${i}`, aRva, aSize, bRva, bSize, kind });
  }

  // ---- imports ----
  const modKey = (m: { dll: string; delayLoaded: boolean }) => `${m.dll.toLowerCase()}|${m.delayLoaded ? 'd' : 'n'}`;
  const aMods = new Map(a.imports.map((m) => [modKey(m), m]));
  const bMods = new Map(b.imports.map((m) => [modKey(m), m]));
  const imports: ImportDiff[] = [];
  for (const [key, ma] of aMods) {
    const mb = bMods.get(key);
    const aNames = new Set(ma.symbols.map((s) => s.name));
    if (!mb) {
      imports.push({
        dll: ma.dll,
        kind: 'removed',
        category: ma.category,
        delayLoaded: ma.delayLoaded,
        added: [],
        removed: [...aNames],
        commonCount: 0,
      });
      continue;
    }
    const bNames = new Set(mb.symbols.map((s) => s.name));
    const added = [...bNames].filter((n) => !aNames.has(n)).sort();
    const removed = [...aNames].filter((n) => !bNames.has(n)).sort();
    imports.push({
      dll: ma.dll,
      kind: added.length || removed.length ? 'changed' : 'same',
      category: ma.category,
      delayLoaded: ma.delayLoaded,
      added,
      removed,
      commonCount: [...aNames].filter((n) => bNames.has(n)).length,
    });
  }
  for (const [key, mb] of bMods) {
    if (aMods.has(key)) continue;
    imports.push({
      dll: mb.dll,
      kind: 'added',
      category: mb.category,
      delayLoaded: mb.delayLoaded,
      added: mb.symbols.map((s) => s.name).sort(),
      removed: [],
      commonCount: 0,
    });
  }
  imports.sort((x, y) => {
    const rank = (k: ChangeKind) => (k === 'added' ? 0 : k === 'removed' ? 1 : k === 'changed' ? 2 : 3);
    return rank(x.kind) - rank(y.kind) || x.dll.localeCompare(y.dll);
  });

  // ---- exports ----
  const named = (p: PEImage) => new Map((p.exports?.symbols ?? []).filter((s) => s.name).map((s) => [s.name!, s]));
  const aExp = named(a);
  const bExp = named(b);
  const exports: ExportsDiff = {
    added: [],
    removed: [],
    moved: [],
    ordinalChanged: [],
    forwarderChanged: [],
    unchanged: 0,
  };
  for (const [name, sa] of aExp) {
    const sb = bExp.get(name);
    if (!sb) {
      exports.removed.push(sa);
      continue;
    }
    let touched = false;
    if (sa.rva !== sb.rva) {
      exports.moved.push({ name, ordinal: sb.ordinal, aRva: sa.rva, bRva: sb.rva });
      touched = true;
    }
    if (sa.ordinal !== sb.ordinal) {
      exports.ordinalChanged.push({ name, a: sa.ordinal, b: sb.ordinal });
      touched = true;
    }
    if ((sa.forwarder ?? '') !== (sb.forwarder ?? '')) {
      exports.forwarderChanged.push({ name, a: sa.forwarder, b: sb.forwarder });
      touched = true;
    }
    if (!touched) exports.unchanged++;
  }
  for (const [name, sb] of bExp) if (!aExp.has(name)) exports.added.push(sb);
  exports.added.sort((x, y) => (x.name ?? '').localeCompare(y.name ?? ''));
  exports.removed.sort((x, y) => (x.name ?? '').localeCompare(y.name ?? ''));

  // ---- resources ----
  const aRes = flattenResources(a.resources);
  const bRes = flattenResources(b.resources);
  const resources: ResourceDiff[] = [];
  for (const [path, size] of aRes) {
    if (!bRes.has(path)) resources.push({ path, kind: 'removed', aSize: size });
    else {
      const bSize = bRes.get(path)!;
      resources.push({ path, kind: bSize === size ? 'same' : 'changed', aSize: size, bSize });
    }
  }
  for (const [path, size] of bRes) if (!aRes.has(path)) resources.push({ path, kind: 'added', bSize: size });
  resources.sort((x, y) => {
    const rank = (k: ChangeKind) => (k === 'added' ? 0 : k === 'removed' ? 1 : k === 'changed' ? 2 : 3);
    return rank(x.kind) - rank(y.kind) || x.path.localeCompare(y.path);
  });

  // ---- similarity ----
  let weighted = 0;
  let weight = 0;
  sections.forEach((s) => {
    if (s.similarity === null || !s.a || !s.b) return;
    const w = Math.max(s.a.rawSize, s.b.rawSize);
    weighted += s.similarity * w;
    weight += w;
  });
  const similarity = weight ? weighted / weight : 0;

  const counts = {
    sectionsAdded: sections.filter((s) => s.kind === 'added').length,
    sectionsRemoved: sections.filter((s) => s.kind === 'removed').length,
    sectionsChanged: sections.filter((s) => s.kind === 'changed').length,
    modulesAdded: imports.filter((m) => m.kind === 'added').length,
    modulesRemoved: imports.filter((m) => m.kind === 'removed').length,
    functionsAdded: imports.reduce((n, m) => n + m.added.length, 0),
    functionsRemoved: imports.reduce((n, m) => n + m.removed.length, 0),
    exportsAdded: exports.added.length,
    exportsRemoved: exports.removed.length,
    exportsMoved: exports.moved.length,
    resourcesAdded: resources.filter((r) => r.kind === 'added').length,
    resourcesRemoved: resources.filter((r) => r.kind === 'removed').length,
    resourcesChanged: resources.filter((r) => r.kind === 'changed').length,
    mitigationsChanged: mitigations.filter((m) => m.a !== m.b).length,
  };

  // ---- headline narrative ----
  const headline: string[] = [];
  const sizeDelta = b.fileSize - a.fileSize;
  if (a.machine !== b.machine || a.is64 !== b.is64) {
    headline.push(`Architecture changed from ${a.machineName} to ${b.machineName} — this is not the same binary contract.`);
  }
  headline.push(
    sizeDelta === 0
      ? `Both files are ${formatSize(a.fileSize)}.`
      : `The file ${sizeDelta > 0 ? 'grew' : 'shrank'} by ${formatSize(Math.abs(sizeDelta))} (${signed(Math.round((sizeDelta / a.fileSize) * 1000) / 10)}%), and the mapped image ${
          b.sizeOfImage === a.sizeOfImage ? 'stayed the same size' : `${b.sizeOfImage > a.sizeOfImage ? 'grew' : 'shrank'} by ${formatSize(Math.abs(b.sizeOfImage - a.sizeOfImage))}`
        }.`,
  );
  if (weight) headline.push(`${Math.round(similarity * 100)}% of the mapped section bytes are byte-for-byte identical.`);
  if (counts.sectionsAdded || counts.sectionsRemoved) {
    headline.push(
      `Section table changed: ${counts.sectionsAdded} added, ${counts.sectionsRemoved} removed, ${counts.sectionsChanged} modified.`,
    );
  } else if (counts.sectionsChanged) {
    headline.push(`${counts.sectionsChanged} of ${a.sections.length} sections changed; the section table itself is unchanged.`);
  }
  if (counts.modulesAdded || counts.modulesRemoved) {
    headline.push(
      `Dependencies changed: ${counts.modulesAdded ? `now also needs ${imports.filter((m) => m.kind === 'added').map((m) => m.dll).join(', ')}` : ''}${
        counts.modulesAdded && counts.modulesRemoved ? '; ' : ''
      }${counts.modulesRemoved ? `no longer needs ${imports.filter((m) => m.kind === 'removed').map((m) => m.dll).join(', ')}` : ''}.`,
    );
  }
  if (counts.functionsAdded || counts.functionsRemoved) {
    headline.push(`${counts.functionsAdded} imported functions added, ${counts.functionsRemoved} removed.`);
  }
  if (counts.exportsAdded || counts.exportsRemoved) {
    headline.push(
      `Public API surface changed: ${counts.exportsAdded} exports added, ${counts.exportsRemoved} removed${
        counts.exportsRemoved ? ' — removing an export is a breaking change for anything bound to it' : ''
      }.`,
    );
  }
  if (counts.mitigationsChanged) {
    const worse = mitigations.filter((m) => m.a && !m.b).map((m) => m.name);
    const better = mitigations.filter((m) => !m.a && m.b).map((m) => m.name);
    if (worse.length) headline.push(`Mitigations were turned OFF: ${worse.join(', ')}.`);
    if (better.length) headline.push(`Mitigations were turned ON: ${better.join(', ')}.`);
  }
  if (!counts.sectionsChanged && !counts.sectionsAdded && !counts.sectionsRemoved && sizeDelta === 0 && similarity === 1) {
    headline.push('These two images look functionally identical.');
  }

  return {
    a,
    b,
    identity,
    layout,
    build,
    versionInfo,
    mitigations,
    sections,
    directories,
    imports,
    exports,
    resources,
    similarity,
    headline,
    counts,
  };
}
