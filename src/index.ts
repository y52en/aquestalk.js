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
} from "./clib_hook.js";
import {
  Heap,
  NOP_CODE,
  hook_lib_call,
  reg_read_uint32,
  reg_write_uint32,
} from "./emu_util.js";
import { parsePE } from "./pe.js";
import { NATIVE_CLIB_BIN, NATIVE_CLIB_SYMBOLS } from "./native_code.js";

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
  readonly HEAP_LENGTH = 0x1000_0000;
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

    // Reset CPU registers and segments before starting a new run
    emu.reset_cpu();
    this.#reset_esp();

    // Reload DLL memory to BASE_ADDRESS to reset any global state
    emu.mem_write(this.#baseAddress, new Uint8Array(this.#dll_file));
    // Reset _adjust_fdiv and other low-memory state
    if (this.#adjustFdivTargetAddress) {
      emu.mem_write(this.#adjustFdivTargetAddress, to_bytes_uint32(0));
    }

    // Write native CLIB code to heap
    const native_code_addr = this.#heap.set_mem_value(emu, NATIVE_CLIB_BIN);

    // Apply native hooks by overwriting IAT entries
    const nativeHookMap: { [key: string]: number } = {
      strncmp: NATIVE_CLIB_SYMBOLS.strncmp,
      strncpy: NATIVE_CLIB_SYMBOLS.strncpy,
      strtok: NATIVE_CLIB_SYMBOLS.strtok,
      strchr: NATIVE_CLIB_SYMBOLS.strchr,
      stricmp: NATIVE_CLIB_SYMBOLS.stricmp,
      _stricmp: NATIVE_CLIB_SYMBOLS.stricmp,
      _initterm: NATIVE_CLIB_SYMBOLS._initterm,
      initterm: NATIVE_CLIB_SYMBOLS._initterm,
      __CxxFrameHandler: NATIVE_CLIB_SYMBOLS.__CxxFrameHandler,
      DisableThreadLibraryCalls: NATIVE_CLIB_SYMBOLS.DisableThreadLibraryCalls,
    };

    for (const [name, offset] of Object.entries(nativeHookMap)) {
      const info = this.#iatHooks[name];
      if (info) {
        emu.mem_write(
          this.#baseAddress + info.rva,
          to_bytes_uint32(native_code_addr + offset)
        );
      }
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
