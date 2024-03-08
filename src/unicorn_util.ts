import { from_bytes_uint32, to_bytes_uint32 } from "./util";

const uc = window.uc;

export class Heap {
  readonly heap_addr: number;
  readonly heap_len: number;
  heap_used = 0;

  constructor(mu: Uc, heap_addr: number, heap_len = 0) {
    this.heap_addr = heap_addr;
    this.heap_len = heap_len;
    this.#create_heap(mu);
  }

  set_mem_value(mu: Uc, value: Uint8Array): number {
    const write_address = this.heap_addr + this.heap_used;
    if (write_address + value.length >= this.heap_addr + this.heap_len) {
      throw new Error("heap over");
    }
    mu.mem_write(write_address, value);
    this.heap_used += value.length;
    return write_address;
  }

  #create_heap(mu: Uc) {
    mu.mem_map(this.heap_addr, this.heap_len, uc.PROT_ALL);
  }

  clear_heap(mu: Uc) {
    mu.mem_unmap(this.heap_addr, this.heap_len);
    this.heap_used = 0;
    this.#create_heap(mu);
  }
}

export const NOP_CODE = new Uint8Array([0x90]);

export function hook_lib_call(
  mu: Uc,
  address: number,
  callback: (mu: Uc, ...args: any[]) => void,
  arg: any = null
) {
  mu.mem_write(address, NOP_CODE);
  mu.hook_add(
    uc.HOOK_CODE,
    (...arg) => {
      callback(...arg);
    },
    arg,
    address,
    address + 4
  );
}

export function reg_read_uint32(mu: Uc, reg: number): number {
  return from_bytes_uint32(mu.reg_read(reg, 4));
}

export function reg_write_uint32(mu: Uc, reg: number, value: number) {
  mu.reg_write(reg, to_bytes_uint32(value));
}

export function align_to_0x1000(number: number): number {
  return Math.floor((number + 0xfff) / 0x1000) * 0x1000;
}
