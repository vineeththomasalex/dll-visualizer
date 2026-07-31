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
  export const Const: Record<string, number>;
}
