// 不完全、最低限のもののみ
declare class Uc {
  constructor(arch: number, mode: number): Uc;
  reg_write: (reg: number, value: Uint8Array) => void;
  reg_read: (reg: number, size: number) => Uint8Array;
  mem_write: (addr: number, data: Uint8Array) => void;
  mem_read: (addr: number, size: number) => Uint8Array;
  mem_map: (addr: number, size: number, prot: number) => void;
  mem_unmap: (addr: number, size: number) => void;
  emu_start: (
    pc: number,
    until: number,
    timeout: number,
    count: number
  ) => void;
  emu_stop: () => void;
  hook_add: <T>(
    type: number,
    callback: (uc: Uc, ...args: [...(any | number), T][]) => void,
    user_data: T,
    begin: number,
    end: number
  ) => void;
}
