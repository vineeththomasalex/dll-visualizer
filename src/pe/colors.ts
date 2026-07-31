import type { PESection } from './types';

/** Muted, cohesive palette keyed by what a section actually holds. */
export const SECTION_COLORS: Record<string, string> = {
  code: '#5b8dd9',
  rdata: '#4fb3a5',
  data: '#c9885f',
  bss: '#8f7bb8',
  reloc: '#a8a35e',
  rsrc: '#c96f9e',
  pdata: '#6f9ec9',
  debug: '#7d8799',
  tls: '#b97ec9',
  clr: '#5fb87f',
  other: '#7f8494',
};

export const DIRECTORY_COLOR: Record<number, string> = {
  0: '#7fd6a8', // exports
  1: '#ffd479', // imports
  2: '#f090c0', // resources
  3: '#8fb8f0', // exceptions
  4: '#d4a5ff', // certificates
  5: '#e0d98a', // relocations
  6: '#9fb0c4', // debug
  9: '#d49bf0', // TLS
  10: '#ff9f9f', // load config
  11: '#c0c0a0', // bound import
  12: '#ffc178', // IAT
  13: '#ffb0a0', // delay import
  14: '#7fe0a8', // CLR
};

export function colorForSection(s: PESection): string {
  const n = s.name.toLowerCase();
  const ch = s.characteristics;
  if (n.startsWith('.text') || n.startsWith('.code') || n === 'code') return SECTION_COLORS.code;
  if (n.startsWith('.rdata') || n.startsWith('.rodata')) return SECTION_COLORS.rdata;
  if (n.startsWith('.data')) return SECTION_COLORS.data;
  if (n.startsWith('.bss')) return SECTION_COLORS.bss;
  if (n.startsWith('.reloc')) return SECTION_COLORS.reloc;
  if (n.startsWith('.rsrc')) return SECTION_COLORS.rsrc;
  if (n.startsWith('.pdata') || n.startsWith('.xdata')) return SECTION_COLORS.pdata;
  if (n.startsWith('.debug') || n.startsWith('.pdb')) return SECTION_COLORS.debug;
  if (n.startsWith('.tls')) return SECTION_COLORS.tls;
  if (n.startsWith('.cormeta') || n.startsWith('.sdata')) return SECTION_COLORS.clr;
  if (ch & 0x20000000) return SECTION_COLORS.code;
  if (ch & 0x80000000) return SECTION_COLORS.data;
  if (ch & 0x00000040) return SECTION_COLORS.rdata;
  return SECTION_COLORS.other;
}

export const PERM_COLOR: Record<string, string> = {
  'R-X': '#5b8dd9',
  'R--': '#4fb3a5',
  'RW-': '#c9885f',
  RWX: '#e0524f',
  '---': '#5a5f70',
};
