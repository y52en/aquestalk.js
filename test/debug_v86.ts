#!/usr/bin/env node
/**
 * Debug test: trace hook execution in v86 to find the problem
 */
const fs = require('fs');
const path = require('path');
const JSZip = require('jszip');

async function main() {
  // Load modules dynamically since they're ESM
  const { V86Emu, REG_EAX, REG_ESP } = require('../src/v86_emu');
  const { Heap, hook_lib_call, reg_read_uint32, reg_write_uint32 } = require('../src/unicorn_util');
  const { push, call, ret, get_arg, jmp } = require('../src/x86_util');
  const { to_bytes_uint32, from_bytes_uint32, convert_sjis, uint8array_concat } = require('../src/util');

  console.log("=== Debug Hook Test ===");

  // Load DLL
  const zipBuf = fs.readFileSync(path.join(__dirname, '..', 'docs', 'f1.zip'));
  const zip = new JSZip();
  const zipRoot = await zip.loadAsync(zipBuf);
  const dllFile = await zipRoot.files['f1/AquesTalk.dll'].async('arraybuffer');

  // Initialize v86
  const emu = new V86Emu();
  const wasmPath = path.join(__dirname, '..', 'node_modules', 'v86', 'build', 'v86.wasm');
  await emu.init({ wasmPath, memorySize: 1024 * 1024 * 1024 });

  const BASE_ADDRESS = 0x10000000;
  const HEAP_ADDRESS = 0x20000000;
  const HEAP_LENGTH = 0x1000000;

  // Load DLL at BASE_ADDRESS
  emu.mem_write(BASE_ADDRESS, new Uint8Array(dllFile));

  // Create heap
  const heap = new Heap(emu, HEAP_ADDRESS, HEAP_LENGTH);
  reg_write_uint32(emu, REG_ESP, HEAP_ADDRESS + HEAP_LENGTH);

  // Install hooks with debug logging
  let hookCount = 0;
  
  hook_lib_call(emu, 0x0001765c, (emu2, userData) => {
    hookCount++;
    const arg0 = get_arg(emu2, 0);
    console.log(`[HOOK#${hookCount}] malloc called, size=${arg0}, ESP=0x${reg_read_uint32(emu2, REG_ESP).toString(16)}, EIP=0x${emu2.get_eip().toString(16)}`);
    
    const addr = heap.set_mem_value(emu2, new Uint8Array(arg0).fill(0));
    console.log(`  → returned addr=0x${addr.toString(16)}`);
    reg_write_uint32(emu2, REG_EAX, addr);
    
    const retAddr = from_bytes_uint32(emu2.mem_read(reg_read_uint32(emu2, REG_ESP), 4));
    console.log(`  → will ret to 0x${retAddr.toString(16)}`);
    
    ret(emu2);
    console.log(`  → after ret: EIP=0x${emu2.get_eip().toString(16)}, ESP=0x${reg_read_uint32(emu2, REG_ESP).toString(16)}`);
  });
  
  hook_lib_call(emu, 0x00017654, (emu2, userData) => {
    hookCount++;
    console.log(`[HOOK#${hookCount}] free called, ESP=0x${reg_read_uint32(emu2, REG_ESP).toString(16)}, EIP=0x${emu2.get_eip().toString(16)}`);
    ret(emu2);
    console.log(`  → after ret: EIP=0x${emu2.get_eip().toString(16)}`);
  });
  
  hook_lib_call(emu, 0x00017666, (emu2, userData) => {
    hookCount++;
    console.log(`[HOOK#${hookCount}] strncmp called, ESP=0x${reg_read_uint32(emu2, REG_ESP).toString(16)}`);
    const str0 = get_arg(emu2, 0);
    const str1 = get_arg(emu2, 1);
    const max_len = get_arg(emu2, 2);
    let result = 0;
    for (let i = 0; i < max_len; i++) {
      if (emu2.mem_read(str0 + i, 1)[0] !== emu2.mem_read(str1 + i, 1)[0]) {
        result = emu2.mem_read(str0 + i, 1)[0] - emu2.mem_read(str1 + i, 1)[0];
        break;
      }
    }
    reg_write_uint32(emu2, REG_EAX, result);
    ret(emu2);
    console.log(`  → after ret: EIP=0x${emu2.get_eip().toString(16)}`);
  });
  
  hook_lib_call(emu, 0x00017670, (emu2, userData) => {
    hookCount++;
    console.log(`[HOOK#${hookCount}] strncpy called, ESP=0x${reg_read_uint32(emu2, REG_ESP).toString(16)}`);
    const dest = get_arg(emu2, 0);
    const src = get_arg(emu2, 1);
    const count = get_arg(emu2, 2);
    emu2.mem_write(dest, emu2.mem_read(src, count));
    reg_write_uint32(emu2, REG_EAX, dest);
    ret(emu2);
    console.log(`  → after ret: EIP=0x${emu2.get_eip().toString(16)}`);
  });

  // Set up strncmp code
  const _strncmp = "8b ff 55 8b ec 53 56 8b 75 10 33 d2 57 85 f6 0f 84 8a 00 00 00 83 fe 04 72 68 8d 7e fc 85 ff 74 61 8b 4d 0c 8b 45 08 8a 18 83 c0 04 83 c1 04 84 db 74 44 3a 59 fc 75 3f 8a 58 fd 84 db 74 32 3a 59 fd 75 2d 8a 58 fe 84 db 74 20 3a 59 fe 75 1b 8a 58 ff 84 db 74 0e 3a 59 ff 75 09 83 c2 04 3b d7 72 c4 eb 23 0f b6 49 ff eb 10 0f b6 49 fe eb 0a 0f b6 49 fd eb 04 0f b6 49 fc 0f b6 c3 2b c1 eb 1f 8b 4d 0c 8b 45 08 3b d6 73 13 2b c1 8a 1c 08 84 db 74 11 3a 19 75 0d 42 41 3b d6 72 ef 33 c0 5f 5e 5b 5d c3 0f b6 09 eb d0";
  const strncmp = new Uint8Array(_strncmp.split(" ").map(v => parseInt(v, 16)));
  
  const strncmp_addr_place = 0x1000700c;
  const strncmp_fn = heap.set_mem_value(emu, strncmp);
  emu.mem_write(strncmp_addr_place, to_bytes_uint32(strncmp_fn));

  const koe = "テスト";
  const size = heap.set_mem_value(emu, new Uint8Array(8).fill(0));
  const koe_addr = heap.set_mem_value(emu, uint8array_concat(convert_sjis(koe), new Uint8Array([0x0])));

  push(emu, size);
  push(emu, 100); // speed
  push(emu, koe_addr);

  const NOP_CODE = 0x90;
  const return_fn_addr = heap.set_mem_value(emu, new Uint8Array(4).fill(NOP_CODE));
  emu.set_eip(return_fn_addr);
  call(emu, BASE_ADDRESS + 0x15f0); // AquesTalk_Synthe

  console.log(`Starting emulation: EIP=0x${emu.get_eip().toString(16)}, until=0x${return_fn_addr.toString(16)}`);
  
  try {
    emu.emu_start(emu.get_eip(), return_fn_addr);
    console.log("Emulation completed successfully!");
    console.log(`EAX: 0x${reg_read_uint32(emu, REG_EAX).toString(16)}`);
  } catch (e) {
    console.error(`Emulation failed at EIP: 0x${emu.get_eip().toString(16)}`);
    console.error(e.message || e);
  }
}
main().catch(console.error);
