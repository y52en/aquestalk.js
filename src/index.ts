import JSZip from "jszip";
import { V86Emu, REG_EAX, REG_ESP } from "./v86_emu";
import { call, push } from "./x86_util";
import {
  convert_sjis,
  from_bytes_uint32,
  to_bytes_uint32,
  uint8array_concat,
} from "./util";
import {
  free_hook,
  malloc_hook,
  strncmp_hook,
  strncpy_hook,
  strtok_hook,
  strchr_hook,
  stricmp_hook,
  initterm_hook,
  cxx_frame_handler_hook,
  disable_thread_library_calls_hook,
} from "./clib_hook";
import {
  Heap,
  NOP_CODE,
  hook_lib_call,
  reg_read_uint32,
  reg_write_uint32,
} from "./emu_util";

const _strncmp =
  "8b ff 55 8b ec 53 56 8b 75 10 33 d2 57 85 f6 0f 84 8a 00 00 00 83 fe 04 72 68 8d 7e fc 85 ff 74 61 8b 4d 0c 8b 45 08 8a 18 83 c0 04 83 c1 04 84 db 74 44 3a 59 fc 75 3f 8a 58 fd 84 db 74 32 3a 59 fd 75 2d 8a 58 fe 84 db 74 20 3a 59 fe 75 1b 8a 58 ff 84 db 74 0e 3a 59 ff 75 09 83 c2 04 3b d7 72 c4 eb 23 0f b6 49 ff eb 10 0f b6 49 fe eb 0a 0f b6 49 fd eb 04 0f b6 49 fc 0f b6 c3 2b c1 eb 1f 8b 4d 0c 8b 45 08 3b d6 73 13 2b c1 8a 1c 08 84 db 74 11 3a 19 75 0d 42 41 3b d6 72 ef 33 c0 5f 5e 5b 5d c3 0f b6 09 eb d0";
const strncmp = new Uint8Array(_strncmp.split(" ").map((v) => parseInt(v, 16)));

export class AquesTalk {
  readonly #dll_file;
  readonly #emu;

  readonly BASE_ADDRESS = 0x1000_0000;
  readonly AquesTalk_Synthe = this.BASE_ADDRESS + 0x15f0;
  readonly HEAP_ADDRESS = 0x2000_0000;
  readonly HEAP_LENGTH = 0x100_0000;
  // init内で初期化するため、nullで初期化
  #heap: Heap = null as unknown as Heap;
  constructor(file: ArrayBuffer, emu: V86Emu) {
    this.#dll_file = file;
    this.#emu = emu;
    this.#init();
  }

  #reset_esp() {
    reg_write_uint32(
      this.#emu,
      REG_ESP,
      this.HEAP_ADDRESS + this.HEAP_LENGTH
    );
  }

  #init() {
    const emu = this.#emu;

    // v86 has flat memory - no need for mem_map, just write directly
    // Write the DLL into memory at BASE_ADDRESS
    emu.mem_write(this.BASE_ADDRESS, new Uint8Array(this.#dll_file));

    // Initialize heap
    this.#heap = new Heap(emu, this.HEAP_ADDRESS, this.HEAP_LENGTH);
    this.#reset_esp();

    hook_lib_call(emu, 0x0001765c, malloc_hook, (emu: V86Emu, value: Uint8Array) =>
      this.#heap.set_mem_value(emu, value)
    );
    hook_lib_call(emu, 0x00017666, strncmp_hook);
    hook_lib_call(emu, 0x00017670, strncpy_hook);
    hook_lib_call(emu, 0x00017654, free_hook);
    hook_lib_call(emu, 0x0001767a, strtok_hook);
    hook_lib_call(emu, 0x0001769a, initterm_hook);
    hook_lib_call(emu, 0x00017684, strchr_hook);
    hook_lib_call(emu, 0x00017640, cxx_frame_handler_hook);
    hook_lib_call(emu, 0x000176e0, stricmp_hook);
    hook_lib_call(emu, 0x000176b6, disable_thread_library_calls_hook);

    // _adjust_fdiv is a DATA import (int variable), not a function.
    // The DLL does: mov eax,[IAT_entry] → reads value at that address.
    // We write 0 (no Pentium FDIV bug) at the IAT target address.
    // IAT entry at BASE+0x7020 points to RVA 0x176a6.
    // We need to write 0 at address 0x176a6.
    emu.mem_write(0x000176a6, to_bytes_uint32(0));
  }

  #reset() {
    this.#heap.clear_heap(this.#emu);
    reg_write_uint32(this.#emu, REG_EAX, 0);
    this.#reset_esp();
  }

  run(koe: string, speed: number = 100) {
    const emu = this.#emu;

    const strncmp_addr_place = 0x1000700c;
    const strncmp_fn = this.#heap.set_mem_value(emu, strncmp);
    emu.mem_write(strncmp_addr_place, to_bytes_uint32(strncmp_fn));

    const size = this.#heap.set_mem_value(emu, new Uint8Array(8).fill(0));
    const koe_addr = this.#heap.set_mem_value(
      emu,
      uint8array_concat(convert_sjis(koe), new Uint8Array([0x0]))
    );

    push(emu, size);
    push(emu, speed);
    push(emu, koe_addr);

    const return_fn_addr = this.#heap.set_mem_value(
      emu,
      new Uint8Array(1048576).fill(NOP_CODE[0])
    );
    emu.set_eip(return_fn_addr);
    call(emu, this.AquesTalk_Synthe);

    try {
      emu.emu_start(emu.get_eip(), return_fn_addr);
    } catch (e) {
      console.error(e);
      console.error(
        `error at: EIP: `,
        emu.get_eip().toString(16)
      );
      console.error(
        `error at: ESP:`,
        reg_read_uint32(emu, REG_ESP).toString(16)
      );
      this.#reset();

      throw e;
    }

    const size_value = from_bytes_uint32(emu.mem_read(size, 4));
    const return_value = reg_read_uint32(emu, REG_EAX);

    if (return_value === 0) {
      throw new Error(`AquesTalk_Synthe error. ERROR CODE: ${size_value}`);
    }
    const result = emu.mem_read(return_value, size_value);

    this.#reset();
    return result;
  }
}

export async function loadAquesTalk(
  zippath: string,
  dllpath: string,
  options: { memorySize?: number; wasmPath?: string } = {}
) {
  const zip = new JSZip();
  const zipbin = await (await fetch(zippath)).arrayBuffer();
  const ziproot = await zip.loadAsync(zipbin);
  const dllfile = await ziproot.files[dllpath].async("arraybuffer");

  // Initialize v86 emulator
  const emu = new V86Emu();

  // In browser environments, default wasmPath to ./v86.wasm if not provided
  if (!options.wasmPath && typeof window !== "undefined") {
    options.wasmPath = "./v86.wasm";
  }

  await emu.init(options);

  return new AquesTalk(dllfile, emu);
}
