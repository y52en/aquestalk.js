import { describe, expect, it, vi } from "vitest";

import { Heap } from "../src/emu_util.js";
import { V86Emu } from "../src/v86_emu.js";

function createEmulatorMock(): V86Emu {
  return {
    mem_write: vi.fn(),
    mem_clear: vi.fn(),
  } as unknown as V86Emu;
}

describe("Heap", () => {
  it("does not allocate or zero the entire heap during construction", () => {
    const emu = createEmulatorMock();

    new Heap(emu, 0x1000, 1024 * 1024);

    expect(emu.mem_write).not.toHaveBeenCalled();
    expect(emu.mem_clear).not.toHaveBeenCalled();
  });

  it("aligns allocations and permits an exact fit", () => {
    const emu = createEmulatorMock();
    const heap = new Heap(emu, 0x1000, 8);

    expect(heap.allocate(1)).toBe(0x1000);
    expect(heap.allocate(4)).toBe(0x1004);
    expect(heap.heap_used).toBe(8);
    expect(() => heap.allocate(1)).toThrow("heap over");
  });

  it("rejects invalid allocation sizes", () => {
    const heap = new Heap(createEmulatorMock(), 0x1000, 8);

    expect(() => heap.allocate(-1)).toThrow(RangeError);
    expect(() => heap.allocate(1.5)).toThrow(RangeError);
  });

  it("zeroes malloc allocations without creating a source buffer", () => {
    const emu = createEmulatorMock();
    const heap = new Heap(emu, 0x1000, 32);

    expect(heap.allocate_zeroed(emu, 12)).toBe(0x1000);
    expect(emu.mem_clear).toHaveBeenCalledWith(0x1000, 12);
    expect(emu.mem_write).not.toHaveBeenCalled();
  });

  it("can release transient allocations while preserving static data", () => {
    const emu = createEmulatorMock();
    const heap = new Heap(emu, 0x1000, 32);
    heap.allocate(4);
    heap.preserve_allocations();
    heap.allocate(8);

    heap.reset_allocations();

    expect(heap.heap_used).toBe(4);
    expect(emu.mem_clear).not.toHaveBeenCalled();
    expect(heap.allocate(4)).toBe(0x1004);
  });

  it("clears only transient allocations when explicitly requested", () => {
    const emu = createEmulatorMock();
    const heap = new Heap(emu, 0x1000, 32);
    heap.allocate(4);
    heap.preserve_allocations();
    heap.allocate(3);

    heap.clear_heap(emu);

    expect(emu.mem_clear).toHaveBeenCalledWith(0x1004, 3);
    expect(heap.heap_used).toBe(4);
  });
});
