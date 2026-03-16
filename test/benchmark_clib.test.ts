import { vi } from "vitest";
import { stricmp_hook, strchr_hook, strncmp_hook } from "../src/clib_hook.js";

// Mock emulator
class MockEmu {
  memory: Uint8Array;
  constructor(size: number) {
    this.memory = new Uint8Array(size);
  }
  mem_read(addr: number, size: number): Uint8Array {
    return this.memory.slice(addr, addr + size);
  }
  reg_read(reg: number): number {
    return 0; // mocked below if needed
  }
  cpu = {
    reg32: {
      4: 0, // REG_ESP
    }
  };
}

const emu = new MockEmu(1024 * 1024) as any;

// Set up memory
const str0 = 1000;
const str1 = 2000;
const len = 50000; // 50KB strings

for (let i = 0; i < len; i++) {
  emu.memory[str0 + i] = 0x41 + (i % 26); // 'A' to 'Z'
  emu.memory[str1 + i] = 0x61 + (i % 26); // 'a' to 'z'
}
emu.memory[str0 + len] = 0;
emu.memory[str1 + len] = 0;

// Mock get_arg and reg_write_uint32
vi.mock("../src/x86_util.js", () => {
  let callCount = 0;
  return {
    get_arg: (emu: any, argNum: number) => {
      if (argNum === 0) return str0;
      if (argNum === 1) return str1;
      return 0;
    },
    ret: () => {}
  };
});

vi.mock("../src/emu_util.js", () => {
  return {
    reg_write_uint32: () => {}
  };
});

import { test } from 'vitest';

test('benchmark stricmp_hook', () => {
  const start = performance.now();
  for (let j = 0; j < 10000; j++) {
    stricmp_hook(emu);
  }
  const end = performance.now();
  console.log(`stricmp_hook baseline: ${end - start} ms`);
});
