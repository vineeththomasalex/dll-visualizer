import type { PEImage } from '../pe/types';

export interface Instruction {
  address: number;
  rva: number;
  size: number;
  bytes: Uint8Array;
  mnemonic: string;
  opStr: string;
  group: 'flow' | 'call' | 'ret' | 'stack' | 'arith' | 'move' | 'nop' | 'int' | 'other';
  /** Resolved symbolic target for a call/jump, when we can name it. */
  target?: number;
  targetName?: string;
}

type CapstoneModule = {
  Capstone: new (arch: number, mode: number) => {
    disasm: (
      data: Uint8Array,
      options?: { address?: number | bigint; count?: number },
    ) => { address: number | bigint; size: number; bytes: Uint8Array; mnemonic: string; opStr: string }[];
    close: () => void;
  };
  loadCapstone: (args?: Record<string, unknown>) => Promise<void>;
  ARCH: number;
  MODE: number;
};

let modulePromise: Promise<CapstoneModule> | null = null;

async function loadModule(is64: boolean, machine: number): Promise<CapstoneModule> {
  if (!modulePromise) {
    modulePromise = (async () => {
      const cs = await import('capstone-wasm');
      // The wasm binary is emitted as a Vite asset next to the chunk, so the
      // default `new URL('capstone.wasm', import.meta.url)` resolution works
      // under any base path.
      await cs.loadCapstone();
      return cs as unknown as CapstoneModule;
    })();
  }
  const mod = (await modulePromise) as unknown as Record<string, number> & CapstoneModule;
  const arch = machine === 0xaa64 ? mod.CS_ARCH_ARM64 : machine === 0x1c0 || machine === 0x1c4 ? mod.CS_ARCH_ARM : mod.CS_ARCH_X86;
  const mode =
    machine === 0xaa64
      ? mod.CS_MODE_LITTLE_ENDIAN
      : machine === 0x1c0 || machine === 0x1c4
        ? mod.CS_MODE_THUMB
        : is64
          ? mod.CS_MODE_64
          : mod.CS_MODE_32;
  return { ...(mod as unknown as CapstoneModule), ARCH: arch, MODE: mode };
}

export function isArchSupported(machine: number) {
  return machine === 0x14c || machine === 0x8664 || machine === 0xaa64 || machine === 0x1c0 || machine === 0x1c4;
}

const FLOW = /^(j|loop|b\.?|cb|tb)/i;
const CALL = /^(call|bl|blr)/i;
const RET = /^(ret|iret)/i;
const STACK = /^(push|pop|enter|leave|stp|ldp)/i;
const ARITH = /^(add|sub|mul|div|imul|idiv|inc|dec|and|or|xor|not|neg|shl|shr|sar|rol|ror|test|cmp|lea|sbb|adc)/i;
const MOVE = /^(mov|lod|sto|xchg|cmov|ldr|str|movz|movk)/i;
const INT = /^(int|syscall|sysenter|ud2|hlt|brk|svc)/i;

function classify(m: string): Instruction['group'] {
  if (CALL.test(m)) return 'call';
  if (RET.test(m)) return 'ret';
  if (/^nop$/i.test(m)) return 'nop';
  if (INT.test(m)) return 'int';
  if (FLOW.test(m)) return 'flow';
  if (STACK.test(m)) return 'stack';
  if (ARITH.test(m)) return 'arith';
  if (MOVE.test(m)) return 'move';
  return 'other';
}

export async function disassemble(
  pe: PEImage,
  startRva: number,
  byteCount: number,
  nameLookup?: (rva: number) => string | undefined,
): Promise<Instruction[]> {
  const mod = await loadModule(pe.is64, pe.machine);
  const section = pe.sections.find(
    (s) => startRva >= s.virtualAddress && startRva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize),
  );
  if (!section) return [];
  const delta = startRva - section.virtualAddress;
  const available = Math.max(0, Math.min(section.rawSize - delta, pe.bytes.length - (section.rawPointer + delta)));
  const len = Math.min(byteCount, available);
  if (len <= 0) return [];
  const data = pe.bytes.subarray(section.rawPointer + delta, section.rawPointer + delta + len);

  const cs = new mod.Capstone(mod.ARCH, mod.MODE);
  try {
    const insns = cs.disasm(data, { address: startRva });
    return insns.map((i) => {
      const rva = Number(i.address);
      const mnemonic = i.mnemonic;
      const group = classify(mnemonic);
      let target: number | undefined;
      let targetName: string | undefined;
      if ((group === 'call' || group === 'flow') && /^0x[0-9a-f]+$/i.test(i.opStr.trim())) {
        target = parseInt(i.opStr.trim(), 16);
        targetName = nameLookup?.(target);
      }
      // rip-relative indirect call through the IAT: "qword ptr [rip + 0x1234]"
      const ripRel = /\[rip \+ (0x[0-9a-f]+)\]/i.exec(i.opStr);
      if (!targetName && ripRel) {
        const t = rva + i.size + parseInt(ripRel[1], 16);
        target = t;
        targetName = nameLookup?.(t);
      }
      return {
        address: pe.imageBase + rva,
        rva,
        size: i.size,
        bytes: i.bytes,
        mnemonic,
        opStr: i.opStr,
        group,
        target,
        targetName,
      };
    });
  } finally {
    cs.close();
  }
}
