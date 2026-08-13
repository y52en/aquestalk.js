import { describe, it, expect, vi } from "vitest";
import { malloc_hook } from "../src/clib_hook.js";

describe("clib_hook", () => {
  describe("malloc_hook", () => {
    it("should throw an error if the last argument is not a function", () => {
      const emu = {
        reg_read: vi.fn().mockReturnValue(0),
      } as any;

      expect(() => malloc_hook(emu)).toThrow("malloc_hook: last argument must be a function");
      expect(() => malloc_hook(emu, "not a function")).toThrow("malloc_hook: last argument must be a function");
      expect(() => malloc_hook(emu, 123)).toThrow("malloc_hook: last argument must be a function");
      expect(() => malloc_hook(emu, null)).toThrow("malloc_hook: last argument must be a function");
      expect(() => malloc_hook(emu, {})).toThrow("malloc_hook: last argument must be a function");
    });

    it("passes the allocation size without creating a temporary buffer", () => {
      let esp = 0x1000;
      const emu = {
        mem_read_uint32: vi.fn((address: number) =>
          address === 0x1004 ? 64 : 0x1234
        ),
        reg_read: vi.fn(() => esp),
        reg_write: vi.fn((register: number, value: number) => {
          if (register === 4) esp = value;
        }),
        set_eip: vi.fn(),
      } as any;
      const allocate = vi.fn().mockReturnValue(0x2000);

      malloc_hook(emu, allocate);

      expect(allocate).toHaveBeenCalledWith(emu, 64);
      expect(emu.reg_write).toHaveBeenCalledWith(0, 0x2000);
      expect(emu.set_eip).toHaveBeenCalledWith(0x1234);
    });
  });
});
