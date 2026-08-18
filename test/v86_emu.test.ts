import { describe, expect, it, vi } from "vitest";

import { V86Emu } from "../src/v86_emu.js";

describe("V86Emu memory helpers", () => {
  function createEmulator(memorySize = 16): V86Emu {
    const emu = new V86Emu() as any;
    const memory = new Uint8Array(memorySize);
    emu.cpu = {
      memory_size: new Uint32Array([memorySize]),
      mem8: memory,
      read_blob: vi.fn((address: number, size: number) =>
        memory.subarray(address, address + size)
      ),
      write_blob: vi.fn((data: Uint8Array, address: number) =>
        memory.set(data, address)
      ),
    };
    return emu;
  }

  it("reads and writes little-endian uint32 values without buffers", () => {
    const emu = createEmulator();

    emu.mem_write_uint32(4, 0x89abcdef);

    expect(emu.mem_read_uint32(4)).toBe(0x89abcdef);
  });

  it("fills and clears memory in place", () => {
    const emu = createEmulator();

    emu.mem_fill(2, 6, 0xaa);
    emu.mem_clear(4, 2);

    expect([...emu.mem_read(2, 6)]).toEqual([0xaa, 0xaa, 0, 0, 0xaa, 0xaa]);
  });

  it("rejects out-of-range and invalid accesses", () => {
    const emu = createEmulator();

    expect(() => emu.mem_fill(12, 5, 0)).toThrow(RangeError);
    expect(() => emu.mem_read_uint32(-1)).toThrow(RangeError);
    expect(() => emu.assert_memory_range(0, 1.5)).toThrow(RangeError);
  });
});
