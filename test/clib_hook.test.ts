import { describe, it, expect, vi } from "vitest";
import { malloc_hook } from "../src/clib_hook.js";

describe("clib_hook", () => {
  describe("malloc_hook", () => {
    it("should throw an error if the last argument is not a function", () => {
      // Mock the emulator and minimal dependencies needed for get_arg to work
      const emu = {
        mem_read: vi.fn().mockReturnValue(new Uint8Array([0, 0, 0, 0])),
        reg_read: vi.fn().mockReturnValue(0),
        cpu: {
          reg32: {
            4: 0, // REG_ESP
          }
        }
      } as any;

      expect(() => malloc_hook(emu)).toThrow("malloc_hook: last argument must be a function");
      expect(() => malloc_hook(emu, "not a function")).toThrow("malloc_hook: last argument must be a function");
      expect(() => malloc_hook(emu, 123)).toThrow("malloc_hook: last argument must be a function");
      expect(() => malloc_hook(emu, null)).toThrow("malloc_hook: last argument must be a function");
      expect(() => malloc_hook(emu, {})).toThrow("malloc_hook: last argument must be a function");
    });
  });
});
