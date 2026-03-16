import { strchr_hook, stricmp_hook, strncmp_hook } from "../dist/clib_hook.js";

function createMockEmu() {
  const mem = new Uint8Array(1024 * 1024);
  const text1 = "hello world, this is a very long string to test strchr and stricmp performance. We need it to be long enough so the loop runs many times. Z\0";
  const text2 = "hello world, this is a very long string to test strchr and stricmp performance. We need it to be long enough so the loop runs many times. z\0";

  for (let i = 0; i < text1.length; i++) mem[0x1000 + i] = text1.charCodeAt(i);
  for (let i = 0; i < text2.length; i++) mem[0x2000 + i] = text2.charCodeAt(i);

  let esp = 0x10000;

  const regs = { 0: 0 };

  const dv = new DataView(mem.buffer);

  let allocations = 0;

  const emu = {
    mem_read: (addr, size) => {
      allocations++;
      return new Uint8Array(mem.buffer, addr, size);
    },
    mem_write: (addr, data) => {
      mem.set(data, addr);
    },
    reg_read: (reg) => {
      if (reg === 4) return esp;
      return regs[reg];
    },
    reg_write: (reg, val) => {
      if (reg === 4) esp = val;
      else regs[reg] = val;
    },
    get_eip: () => 0x1234,
    set_eip: () => {},
    // memory read for uint32
    cpu: {
      reg32: regs,
      read_blob: (addr, size) => new Uint8Array(mem.buffer, addr, size),
      instruction_pointer: [0x1234],
      get_seg_cs: () => 0
    }
  };

  emu.reg_read = function(reg) {
    if (reg === 4) return esp;
    return regs[reg];
  }

  return { emu, mem, dv, getAllocations: () => allocations, resetAllocations: () => allocations = 0 };
}

function runBenchmark() {
  const { emu, mem, dv, getAllocations, resetAllocations } = createMockEmu();

  resetAllocations();
  let start = performance.now();
  for (let i = 0; i < 1000; i++) {
    dv.setUint32(0x10000 + 4, 0x1000, true);
    dv.setUint32(0x10000 + 8, 'Z'.charCodeAt(0), true);
    strchr_hook(emu);
  }
  let end = performance.now();
  console.log(`strchr_hook: ${end - start} ms, ${getAllocations()} allocations`);

  resetAllocations();
  start = performance.now();
  for (let i = 0; i < 1000; i++) {
    dv.setUint32(0x10000 + 4, 0x1000, true);
    dv.setUint32(0x10000 + 8, 0x2000, true);
    stricmp_hook(emu);
  }
  end = performance.now();
  console.log(`stricmp_hook: ${end - start} ms, ${getAllocations()} allocations`);

  resetAllocations();
  start = performance.now();
  for (let i = 0; i < 1000; i++) {
    dv.setUint32(0x10000 + 4, 0x1000, true);
    dv.setUint32(0x10000 + 8, 0x2000, true);
    dv.setUint32(0x10000 + 12, 100, true);
    strncmp_hook(emu);
  }
  end = performance.now();
  console.log(`strncmp_hook: ${end - start} ms, ${getAllocations()} allocations`);
}

runBenchmark();
