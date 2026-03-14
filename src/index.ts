import JSZip from "jszip";
import { V86Emu, REG_EAX, REG_ESP } from "./v86_emu.js";
import { call, push } from "./x86_util.js";
import {
  convert_sjis,
  from_bytes_uint32,
  to_bytes_uint32,
  uint8array_concat,
} from "./util.js";
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
} from "./clib_hook.js";
import {
  Heap,
  NOP_CODE,
  hook_lib_call,
  reg_read_uint32,
  reg_write_uint32,
} from "./emu_util.js";
import { parsePE } from "./pe.js";

const _strncmp =
  "8b ff 55 8b ec 53 56 8b 75 10 33 d2 57 85 f6 0f 84 8a 00 00 00 83 fe 04 72 68 8d 7e fc 85 ff 74 61 8b 4d 0c 8b 45 08 8a 18 83 c0 04 83 c1 04 84 db 74 44 3a 59 fc 75 3f 8a 58 fd 84 db 74 32 3a 59 fd 75 2d 8a 58 fe 84 db 74 20 3a 59 fe 75 1b 8a 58 ff 84 db 74 0e 3a 59 ff 75 09 83 c2 04 3b d7 72 c4 eb 23 0f b6 49 ff eb 10 0f b6 49 fe eb 0a 0f b6 49 fd eb 04 0f b6 49 fc 0f b6 c3 2b c1 eb 1f 8b 4d 0c 8b 45 08 3b d6 73 13 2b c1 8a 1c 08 84 db 74 11 3a 19 75 0d 42 41 3b d6 72 ef 33 c0 5f 5e 5b 5d c3 0f b6 09 eb d0";
const strncmp = new Uint8Array(_strncmp.split(" ").map((v) => parseInt(v, 16)));

export type Voice = "dvd" | "f1" | "f2" | "imd1" | "jgr" | "m1" | "m2" | "r1";

const VOICE_MAP: Record<Voice, { zip: URL; dll: string }> = {
  dvd: {
    zip: new URL("../voices/dvd.zip", import.meta.url),
    dll: "dvd/AquesTalk.dll",
  },
  f1: {
    zip: new URL("../voices/f1.zip", import.meta.url),
    dll: "f1/AquesTalk.dll",
  },
  f2: {
    zip: new URL("../voices/f2.zip", import.meta.url),
    dll: "f2/AquesTalk.dll",
  },
  imd1: {
    zip: new URL("../voices/imd1.zip", import.meta.url),
    dll: "imd1/AquesTalk.dll",
  },
  jgr: {
    zip: new URL("../voices/jgr.zip", import.meta.url),
    dll: "jgr/AquesTalk.dll",
  },
  m1: {
    zip: new URL("../voices/m1.zip", import.meta.url),
    dll: "m1/AquesTalk.dll",
  },
  m2: {
    zip: new URL("../voices/m2.zip", import.meta.url),
    dll: "m2/AquesTalk.dll",
  },
  r1: {
    zip: new URL("../voices/r1.zip", import.meta.url),
    dll: "r1/AquesTalk.dll",
  },
};

const WASM_URL = new URL("../voices/v86.wasm", import.meta.url);

export interface Options {
  memorySize?: number;
  wasmPath?: string;
}

export class AquesTalk {
  readonly #dll_file;
  readonly #emu;

  #baseAddress = 0x1000_0000;
  #aquesTalk_SyntheAddress = 0;
  #iatHooks: { [key: string]: { rva: number; target: number } } = {};
  #adjustFdivTargetAddress = 0;

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
    reg_write_uint32(this.#emu, REG_ESP, this.HEAP_ADDRESS + this.HEAP_LENGTH);
  }

  #init() {
    const emu = this.#emu;

    const pe = parsePE(this.#dll_file);
    // DLL code expects BASE_ADDRESS typically 0x10000000.
    // We use a hardcoded BASE_ADDRESS for simplicity as the original code did.
    // However, we update it if the PE prefers something else, or just stick to 0x10000000.
    // In f1/f2 it is 0x10000000.
    this.#baseAddress = pe.baseAddress;
    this.#aquesTalk_SyntheAddress = this.#baseAddress + pe.aquesTalkSyntheRVA;
    this.#iatHooks = pe.iatHooks;
    this.#adjustFdivTargetAddress = pe.adjustFdivTarget; // IAT target RVAs are used as ABSOLUTE addresses by unlinked DLLs

    // v86 has flat memory - no need for mem_map, just write directly
    // Write the DLL into memory at baseAddress
    emu.mem_write(this.#baseAddress, new Uint8Array(this.#dll_file));

    // Initialize heap
    this.#heap = new Heap(emu, this.HEAP_ADDRESS, this.HEAP_LENGTH);
    this.#reset_esp();

    const hookMap: { [key: string]: (emu: V86Emu, ...args: any[]) => void } = {
      malloc: malloc_hook,
      free: free_hook,
      strncmp: strncmp_hook,
      strncpy: strncpy_hook,
      strtok: strtok_hook,
      strchr: strchr_hook,
      stricmp: stricmp_hook,
      _stricmp: stricmp_hook,
      _initterm: initterm_hook,
      initterm: initterm_hook,
      __CxxFrameHandler: cxx_frame_handler_hook,
      DisableThreadLibraryCalls: disable_thread_library_calls_hook,
    };

    for (const [name, info] of Object.entries(this.#iatHooks)) {
      if (hookMap[name]) {
        // We hook at the info.target address which is the unlinked address value from IAT.
        // The DLL code jumps to this address when calling imports.
        hook_lib_call(
          emu,
          info.target,
          hookMap[name],
          name === "malloc"
            ? (emu: V86Emu, value: Uint8Array) =>
                this.#heap.set_mem_value(emu, value)
            : undefined
        );
      }
    }

    if (this.#adjustFdivTargetAddress) {
      emu.mem_write(this.#adjustFdivTargetAddress, to_bytes_uint32(0));
    }
  }

  #reset() {
    this.#heap.clear_heap(this.#emu);
    reg_write_uint32(this.#emu, REG_EAX, 0);
    this.#reset_esp();
  }

  run(koe: string, speed: number = 100) {
    const emu = this.#emu;

    // Reload DLL memory to BASE_ADDRESS to reset any global state
    emu.mem_write(this.#baseAddress, new Uint8Array(this.#dll_file));
    // Reset _adjust_fdiv and other low-memory state
    if (this.#adjustFdivTargetAddress) {
      emu.mem_write(this.#adjustFdivTargetAddress, to_bytes_uint32(0));
    }

    // AquesTalk sometimes uses strncmp to check something.
    // Optimization: overwrite IAT entry with native code snippet address.
    const strncmpInfo = this.#iatHooks["strncmp"];
    if (strncmpInfo) {
      const strncmp_fn = this.#heap.set_mem_value(emu, strncmp);
      emu.mem_write(
        this.#baseAddress + strncmpInfo.rva,
        to_bytes_uint32(strncmp_fn)
      );
    }

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
    call(emu, this.#aquesTalk_SyntheAddress);

    try {
      emu.emu_start(emu.get_eip(), return_fn_addr);
    } catch (e) {
      console.error(e);
      console.error(`error at: EIP: `, emu.get_eip().toString(16));
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

  /**
   * Destroy the underlying emulator and release resources.
   */
  async destroy(): Promise<void> {
    await this.#emu.destroy();
  }
}

/**
 * Load AquesTalk by voice name (e.g., "f1").
 * Automatic asset resolution using static new URL().
 */
export async function load(
  voice: Voice,
  options: Options & { baseUrl?: string } = {}
) {
  const { zip, dll } = VOICE_MAP[voice];
  const zipPath = options.baseUrl
    ? new URL(VOICE_MAP[voice].zip.pathname.split("/").pop()!, options.baseUrl)
        .href
    : zip.href;

  // Default wasmPath resolution
  if (!options.wasmPath) {
    options.wasmPath = options.baseUrl
      ? new URL("v86.wasm", options.baseUrl).href
      : WASM_URL.href;
  }

  // Convert to local path if Node.js to avoid fetch/URL issues in v86
  if (
    typeof process !== "undefined" &&
    process.versions &&
    process.versions.node &&
    options.wasmPath.startsWith("file://")
  ) {
    const { fileURLToPath } = await import("url");
    options.wasmPath = fileURLToPath(options.wasmPath);
  }

  return loadAquesTalk(zipPath, dll, options);
}

async function getData(url: string | URL): Promise<ArrayBuffer> {
  const urlStr = url.toString();
  if (
    typeof process !== "undefined" &&
    process.versions &&
    process.versions.node &&
    (urlStr.startsWith("file://") || !urlStr.includes("://"))
  ) {
    const fs = await import("fs/promises");
    const { fileURLToPath } = await import("url");
    const filePath = urlStr.startsWith("file://")
      ? fileURLToPath(urlStr)
      : urlStr;
    const buffer = await fs.readFile(filePath);
    return buffer.buffer.slice(
      buffer.byteOffset,
      buffer.byteOffset + buffer.byteLength
    );
  }
  const response = await fetch(urlStr);
  return response.arrayBuffer();
}

export async function loadAquesTalk(
  zippath: string,
  dllpath: string,
  options: Options = {}
) {
  const zip = new JSZip();
  const zipbin = await getData(zippath);
  const ziproot = await zip.loadAsync(zipbin);
  const dllfile = await ziproot.files[dllpath].async("arraybuffer");

  // Initialize v86 emulator
  const emu = new V86Emu();

  await emu.init(options);

  return new AquesTalk(dllfile, emu);
}
