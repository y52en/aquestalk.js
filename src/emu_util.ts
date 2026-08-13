import { V86Emu } from "./v86_emu.js";

export class Heap {
  readonly heap_addr: number;
  readonly heap_len: number;
  heap_used = 0;
  #reset_position = 0;

  constructor(_emu: V86Emu, heap_addr: number, heap_len = 0) {
    this.heap_addr = heap_addr;
    this.heap_len = heap_len;
  }

  allocate(size: number): number {
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new RangeError(`invalid allocation size: ${size}`);
    }

    const aligned_used = Math.ceil(this.heap_used / 4) * 4;
    if (aligned_used + size > this.heap_len) {
      throw new Error("heap over");
    }

    const address = this.heap_addr + aligned_used;
    this.heap_used = aligned_used + size;
    return address;
  }

  allocate_zeroed(emu: V86Emu, size: number): number {
    const address = this.allocate(size);
    emu.mem_clear(address, size);
    return address;
  }

  set_mem_value(emu: V86Emu, value: Uint8Array): number {
    const write_address = this.allocate(value.length);
    emu.mem_write(write_address, value);
    return write_address;
  }

  preserve_allocations(): void {
    this.#reset_position = this.heap_used;
  }

  reset_allocations(): void {
    this.heap_used = this.#reset_position;
  }

  clear_heap(emu: V86Emu) {
    const clear_length = this.heap_used - this.#reset_position;
    if (clear_length > 0) {
      emu.mem_clear(this.heap_addr + this.#reset_position, clear_length);
    }
    this.heap_used = this.#reset_position;
  }
}

export const NOP = 0x90;

export function hook_lib_call(
  emu: V86Emu,
  address: number,
  callback: (emu: V86Emu, ...args: any[]) => void,
  arg: any = null
) {
  emu.set_hook(
    address,
    (hookEmu: V86Emu, userData: any) => {
      callback(hookEmu, userData);
    },
    arg
  );
}

export function reg_read_uint32(emu: V86Emu, reg: number): number {
  return emu.reg_read(reg);
}

export function reg_write_uint32(emu: V86Emu, reg: number, value: number) {
  emu.reg_write(reg, value);
}

export function align_to_0x1000(number: number): number {
  return Math.floor((number + 0xfff) / 0x1000) * 0x1000;
}
