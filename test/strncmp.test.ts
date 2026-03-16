import { describe, it, expect } from "vitest";
import { strncmp_hook } from "../src/clib_hook.js";

describe("clib_hook", () => {
  describe("strncmp_hook", () => {
    it("performance test", () => {
      const str0 = 0x1000;
      const str1 = 0x2000;
      const max_len = 100000;

      const mem = new Uint8Array(0x3000 + max_len);
      for (let i = 0; i < max_len; i++) {
        mem[str0 + i] = i % 256;
        mem[str1 + i] = i % 256;
      }
      mem[str1 + max_len - 1] = 0; // differ at the end

      let mem_read_calls = 0;

      const emu = {
        mem_read: (addr: number, len: number) => {
          mem_read_calls++;
          return mem.subarray(addr, addr + len);
        },
        reg_read: () => 0,
        reg_write: () => {},
        set_eip: () => {},
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

      write32(4, str0);
      write32(8, str1);
      write32(12, max_len);
      write32(0, 0x12345678);

      const start = performance.now();
      strncmp_hook(emu);
      const end = performance.now();

      console.log(`strncmp_hook took ${end - start} ms, mem_read_calls: ${mem_read_calls}`);
    });
  });
});
