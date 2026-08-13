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

  it("returns a unique freeable allocation for a zero-sized malloc", () => {
    const heap = new Heap(createEmulatorMock(), 0x1000, 8);

    const first = heap.allocate(0);
    const second = heap.allocate(0);

    expect(first).toBe(0x1000);
    expect(second).toBe(0x1004);
    heap.free(first);
    heap.free(second);
    expect(heap.heap_used).toBe(0);
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

  it("returns null from a fallible malloc when the heap is exhausted", () => {
    const emu = createEmulatorMock();
    const heap = new Heap(emu, 0x1000, 8);
    heap.allocate(8);

    expect(heap.try_allocate_zeroed(emu, 4)).toBe(0);
    expect(emu.mem_clear).not.toHaveBeenCalled();
  });

  it("reuses, splits, and coalesces freed allocations", () => {
    const heap = new Heap(createEmulatorMock(), 0x1000, 64);
    const first = heap.allocate(8);
    const second = heap.allocate(16);
    const third = heap.allocate(8);

    heap.free(second);
    expect(heap.allocate(8)).toBe(second + 8);
    expect(heap.allocate(8)).toBe(second);

    heap.free(first);
    heap.free(second);
    heap.free(second + 8);
    heap.free(third);
    expect(heap.heap_used).toBe(0);
  });

  it("rejects pointers that were not returned by malloc", () => {
    const heap = new Heap(createEmulatorMock(), 0x1000, 16);
    const address = heap.allocate(4);
    heap.free(address);

    expect(() => heap.free(address)).toThrow("invalid free address");
    expect(() => heap.free(0x1002)).toThrow("invalid free address");
    expect(() => heap.free(0)).not.toThrow();
  });

  it("never overlaps live allocations under repeated reuse", () => {
    const heap = new Heap(createEmulatorMock(), 0x1000, 4096);
    const live = new Map<number, number>();
    let random = 0x12345678;
    const nextRandom = () => {
      random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
      return random;
    };

    for (let operation = 0; operation < 2000; operation += 1) {
      if (live.size >= 20 || (live.size > 0 && (nextRandom() & 1) === 0)) {
        const addresses = [...live.keys()];
        const address = addresses[nextRandom() % addresses.length];
        heap.free(address);
        live.delete(address);
        continue;
      }

      const size = (nextRandom() % 96) + 1;
      const alignedSize = Math.ceil(size / 4) * 4;
      const address = heap.allocate(size);
      expect(address).toBeGreaterThanOrEqual(0x1000);
      expect(address + alignedSize).toBeLessThanOrEqual(0x2000);
      for (const [otherAddress, otherSize] of live) {
        expect(
          address + alignedSize <= otherAddress ||
            otherAddress + otherSize <= address
        ).toBe(true);
      }
      live.set(address, alignedSize);
    }

    for (const address of live.keys()) heap.free(address);
    expect(heap.heap_used).toBe(0);
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

    expect(emu.mem_clear).toHaveBeenCalledWith(0x1004, 4);
    expect(heap.heap_used).toBe(4);
  });
});
