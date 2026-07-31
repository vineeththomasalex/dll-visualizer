/// <reference types="vite/client" />

declare module 'capstone-wasm' {
  export interface CsInsn {
    id: number;
    address: number | bigint;
    size: number;
    bytes: Uint8Array;
    mnemonic: string;
    opStr: string;
  }
  export class Capstone {
    constructor(arch: number, mode: number);
    disasm(data: Uint8Array | number[], options?: { address?: number | bigint; count?: number }): CsInsn[];
    close(): void;
  }
  export function loadCapstone(args?: Record<string, unknown>): Promise<void>;
  export const CS_ARCH_X86: number;
  export const CS_ARCH_ARM: number;
  export const CS_ARCH_ARM64: number;
  export const CS_MODE_32: number;
  export const CS_MODE_64: number;
  export const CS_MODE_THUMB: number;
  export const CS_MODE_LITTLE_ENDIAN: number;
}

declare module 'capstone-wasm/dist/capstone.wasm?url' {
  const url: string;
  export default url;
}
