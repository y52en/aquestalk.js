import { V86Emu } from "./v86_emu.js";

const HEAP_ALIGNMENT = 4;

interface FreeBlock {
  address: number;
  size: number;
}

export class HeapOutOfMemoryError extends Error {
  constructor() {
    super("heap over");
    this.name = "HeapOutOfMemoryError";
  }
}

export class Heap {
  readonly heap_addr: number;
  readonly heap_len: number;
  heap_used = 0;
  #reset_position = 0;
  #high_water_mark = 0;
  #allocations = new Map<number, number>();
  #free_blocks: FreeBlock[] = [];

  constructor(_emu: V86Emu, heap_addr: number, heap_len = 0) {
    this.heap_addr = heap_addr;
    this.heap_len = heap_len;
  }

  allocate(size: number): number {
    if (!Number.isSafeInteger(size) || size < 0) {
      throw new RangeError(`invalid allocation size: ${size}`);
    }

    // MSVCRT malloc(0) may return a unique, freeable pointer. Reserving one
    // aligned unit preserves that behaviour and avoids duplicate addresses.
    const allocation_size = align_up(Math.max(size, 1), HEAP_ALIGNMENT);

    let best_index = -1;
    for (let index = 0; index < this.#free_blocks.length; index += 1) {
      const block = this.#free_blocks[index];
      if (
        block.size >= allocation_size &&
        (best_index === -1 || block.size < this.#free_blocks[best_index].size)
      ) {
        best_index = index;
      }
    }

    if (best_index !== -1) {
      const block = this.#free_blocks[best_index];
      // Carve reused space from the high end. AquesTalk grows its WAV buffer
      // in 32 KiB steps (malloc new -> copy -> free old); preserving the low
      // edge lets adjacent old buffers coalesce instead of leaving a ladder
      // of unusable fragments.
      const address = block.address + block.size - allocation_size;
      if (block.size === allocation_size) {
        this.#free_blocks.splice(best_index, 1);
      } else {
        block.size -= allocation_size;
      }
      this.#allocations.set(address, allocation_size);
      return address;
    }

    const aligned_used = align_up(this.heap_used, HEAP_ALIGNMENT);
    if (aligned_used + allocation_size > this.heap_len) {
      throw new HeapOutOfMemoryError();
    }

    const address = this.heap_addr + aligned_used;
    this.heap_used = aligned_used + allocation_size;
    this.#high_water_mark = Math.max(this.#high_water_mark, this.heap_used);
    this.#allocations.set(address, allocation_size);
    return address;
  }

  allocate_zeroed(emu: V86Emu, size: number): number {
    const address = this.allocate(size);
    emu.mem_clear(address, size);
    return address;
  }

  try_allocate_zeroed(emu: V86Emu, size: number): number {
    try {
      return this.allocate_zeroed(emu, size);
    } catch (error) {
      if (error instanceof HeapOutOfMemoryError) return 0;
      throw error;
    }
  }

  free(address: number): void {
    if (address === 0) return;

    const size = this.#allocations.get(address);
    if (size === undefined || address < this.heap_addr + this.#reset_position) {
      throw new RangeError(`invalid free address: 0x${address.toString(16)}`);
    }
    this.#allocations.delete(address);

    const block = { address, size };
    let insert_at = 0;
    while (
      insert_at < this.#free_blocks.length &&
      this.#free_blocks[insert_at].address < address
    ) {
      insert_at += 1;
    }
    this.#free_blocks.splice(insert_at, 0, block);
    this.#coalesce_free_blocks();
    this.#release_free_tail();
  }

  set_mem_value(emu: V86Emu, value: Uint8Array): number {
    const write_address = this.allocate(value.length);
    emu.mem_write(write_address, value);
    return write_address;
  }

  preserve_allocations(): void {
    this.#reset_position = this.heap_used;
    this.#high_water_mark = this.heap_used;
    this.#allocations.clear();
    this.#free_blocks.length = 0;
  }

  reset_allocations(): void {
    this.heap_used = this.#reset_position;
    this.#high_water_mark = this.#reset_position;
    this.#allocations.clear();
    this.#free_blocks.length = 0;
  }

  clear_heap(emu: V86Emu) {
    const clear_length = this.#high_water_mark - this.#reset_position;
    if (clear_length > 0) {
      emu.mem_clear(this.heap_addr + this.#reset_position, clear_length);
    }
    this.reset_allocations();
  }

  #coalesce_free_blocks(): void {
    for (let index = 1; index < this.#free_blocks.length; ) {
      const previous = this.#free_blocks[index - 1];
      const current = this.#free_blocks[index];
      if (previous.address + previous.size === current.address) {
        previous.size += current.size;
        this.#free_blocks.splice(index, 1);
      } else {
        index += 1;
      }
    }
  }

  #release_free_tail(): void {
    while (this.#free_blocks.length > 0) {
      const block = this.#free_blocks[this.#free_blocks.length - 1];
      if (block.address + block.size !== this.heap_addr + this.heap_used) return;
      this.heap_used = block.address - this.heap_addr;
      this.#free_blocks.pop();
    }
  }
}

function align_up(value: number, alignment: number): number {
  return Math.ceil(value / alignment) * alignment;
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
