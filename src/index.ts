import JSZip from "jszip";
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
} from "./clib_hook";
import {
  Heap,
  NOP_CODE,
  align_to_0x1000,
  hook_lib_call,
  reg_read_uint32,
  reg_write_uint32,
} from "./unicorn_util";

const _strncmp =
  "8b ff 55 8b ec 53 56 8b 75 10 33 d2 57 85 f6 0f 84 8a 00 00 00 83 fe 04 72 68 8d 7e fc 85 ff 74 61 8b 4d 0c 8b 45 08 8a 18 83 c0 04 83 c1 04 84 db 74 44 3a 59 fc 75 3f 8a 58 fd 84 db 74 32 3a 59 fd 75 2d 8a 58 fe 84 db 74 20 3a 59 fe 75 1b 8a 58 ff 84 db 74 0e 3a 59 ff 75 09 83 c2 04 3b d7 72 c4 eb 23 0f b6 49 ff eb 10 0f b6 49 fe eb 0a 0f b6 49 fd eb 04 0f b6 49 fc 0f b6 c3 2b c1 eb 1f 8b 4d 0c 8b 45 08 3b d6 73 13 2b c1 8a 1c 08 84 db 74 11 3a 19 75 0d 42 41 3b d6 72 ef 33 c0 5f 5e 5b 5d c3 0f b6 09 eb d0";
const strncmp = new Uint8Array(_strncmp.split(" ").map((v) => parseInt(v, 16)));
declare global {
  interface Window {
    uc: {
      Unicorn: typeof Uc;
      readonly X86_REG_ESP: number;
      readonly X86_REG_EIP: number;
      readonly X86_REG_EAX: number;
      readonly HOOK_CODE: number;
      readonly ARCH_X86: number;
      readonly MODE_32: number;
      readonly PROT_READ: number;
      readonly PROT_WRITE: number;
      readonly PROT_EXEC: number;
      readonly PROT_ALL: number;
      readonly HOOK_BLOCK: number;
    };
  }
}

export class AquesTalk {
  readonly #dll_file;
  readonly #mu;

  readonly BASE_ADDRESS = 0x1000_0000;
  readonly AquesTalk_Synthe = this.BASE_ADDRESS + 0x15f0;
  readonly HEAP_ADDRESS = 0x2000_0000;
  readonly HEAP_LENGTH = 0x100_0000;
  // init内で初期化するため、nullで初期化
  #heap: Heap = null as unknown as Heap;
  constructor(file: ArrayBuffer, mu: Uc) {
    this.#dll_file = file;
    this.#mu = mu;
    this.#init();
  }

  #reset_esp() {
    reg_write_uint32(
      this.#mu,
      uc.X86_REG_ESP,
      this.HEAP_ADDRESS + this.HEAP_LENGTH
    );
  }

  #init() {
    const mu = this.#mu;

    const FS_ADDRESS = 0x0000_0000;
    const LIB_SPACE = 0x0001_0000;

    mu.mem_map(
      this.BASE_ADDRESS,
      align_to_0x1000(this.#dll_file.byteLength),
      uc.PROT_ALL
    );
    mu.mem_map(LIB_SPACE, 0x10000, uc.PROT_ALL);
    mu.mem_map(FS_ADDRESS, 0x1000, uc.PROT_ALL);
    this.#heap = new Heap(mu, this.HEAP_ADDRESS, this.HEAP_LENGTH);
    mu.mem_write(this.BASE_ADDRESS, new Uint8Array(this.#dll_file));
    this.#reset_esp();

    hook_lib_call(mu, 0x0001765c, malloc_hook, (mu: Uc, value: Uint8Array) =>
      this.#heap.set_mem_value(mu, value)
    );
    hook_lib_call(mu, 0x00017666, strncmp_hook);

    hook_lib_call(mu, 0x00017670, strncpy_hook);
    hook_lib_call(mu, 0x00017654, free_hook);
  }

  #reset() {
    this.#heap.clear_heap(this.#mu);
    reg_write_uint32(this.#mu, uc.X86_REG_EAX, 0);
    this.#reset_esp();
  }

  run(koe: string, speed: number = 100) {
    const mu = this.#mu;

    const strncmp_addr_place = 0x1000700c;
    const strncmp_fn = this.#heap.set_mem_value(mu, strncmp);
    console.log(`strncmp_fn: ${strncmp_fn}`);
    mu.mem_write(strncmp_addr_place, to_bytes_uint32(strncmp_fn));

    const size = this.#heap.set_mem_value(mu, new Uint8Array(8).fill(0));
    const koe_addr = this.#heap.set_mem_value(
      mu,
      uint8array_concat(convert_sjis(koe), new Uint8Array([0x0]))
    );

    push(mu, size);
    push(mu, speed);
    push(mu, koe_addr);

    const return_fn_addr = this.#heap.set_mem_value(
      mu,
      new Uint8Array(4).fill(NOP_CODE[0])
    );
    reg_write_uint32(mu, uc.X86_REG_EIP, return_fn_addr);
    call(mu, this.AquesTalk_Synthe);

    try {
      mu.emu_start(reg_read_uint32(mu, uc.X86_REG_EIP), return_fn_addr, 0, 0);
    } catch (e) {
      console.error(e);
      console.error(
        `error at: EIP: `,
        reg_read_uint32(mu, uc.X86_REG_EIP).toString(16)
      );
      console.error(
        `error at: ESP:`,
        reg_read_uint32(mu, uc.X86_REG_ESP).toString(16)
      );
      this.#reset();

      throw e;
    }

    const size_value = from_bytes_uint32(mu.mem_read(size, 4));
    const return_value = reg_read_uint32(mu, uc.X86_REG_EAX);
    console.log(`(return value) eax: `, return_value);
    console.log(`*size: `, size_value);

    if (return_value === 0) {
      throw new Error(`AquesTalk_Synthe error. ERROR CODE: ${size_value}`);
    }
    const result = mu.mem_read(return_value, size_value);

    this.#reset();
    return result;
  }
}

const uc = window.uc;

export async function loadAquesTalk(zippath: string, dllpath: string) {
  const zip = new JSZip();
  const zipbin = await (await fetch(zippath)).arrayBuffer();
  const ziproot = await zip.loadAsync(zipbin);
  const dllfile = await ziproot.files[dllpath].async("arraybuffer");
  return new AquesTalk(dllfile, new uc.Unicorn(uc.ARCH_X86, uc.MODE_32));
}
