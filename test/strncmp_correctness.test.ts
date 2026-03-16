import { describe, it, expect } from "vitest";
import { strncmp_hook } from "../src/clib_hook.js";

describe("clib_hook", () => {
  describe("strncmp_hook correctness", () => {
    it("should correctly compare strings", () => {
      const mem = new Uint8Array(1000);
      let eax = 0;
      let eip = 0;

      const emu = {
        mem_read: (addr: number, len: number) => {
          return mem.subarray(addr, addr + len);
        },
        reg_read: () => 0,
        reg_write: (reg: number, val: number) => {
          if (reg === 0) eax = val; // REG_EAX
        },
        set_eip: (addr: number) => { eip = addr; },
        cpu: {
          reg32: {
            4: 0, // REG_ESP
          }
        }
      } as any;

      const write32 = (addr: number, val: number) => {
        mem[addr] = val & 0xff;
        mem[addr+1] = (val >> 8) & 0xff;
        mem[addr+2] = (val >> 16) & 0xff;
        mem[addr+3] = (val >> 24) & 0xff;
      };

      const writeString = (addr: number, str: string) => {
        for (let i = 0; i < str.length; i++) {
          mem[addr + i] = str.charCodeAt(i);
        }
        mem[addr + str.length] = 0;
      };

      // Test 1: identical strings
      write32(4, 100);
      write32(8, 200);
      write32(12, 5); // max len
      writeString(100, "hello");
      writeString(200, "hello");
      strncmp_hook(emu);
      expect(eax).toBe(0);

      // Test 2: different strings, same length, diff at index 2
      writeString(100, "heXlo");
      writeString(200, "hello");
      strncmp_hook(emu);
      expect(eax).toBe("X".charCodeAt(0) - "l".charCodeAt(0));

      // Test 3: max_len stops comparison before diff
      write32(12, 2); // max len
      strncmp_hook(emu);
      expect(eax).toBe(0);
    });
  });
});
