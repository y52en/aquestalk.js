import JSZip from "jszip";
import { V86Emu, REG_EAX, REG_ESP } from "./v86_emu.js";
import { call, push } from "./x86_util.js";
import { convert_sjis } from "./util.js";
import { free_hook, malloc_hook } from "./clib_hook.js";
import {
  Heap,
  NOP,
  align_to_0x1000,
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
  heapSize?: number;
}

export const DEFAULT_HEAP_SIZE = 8 * 1024 * 1024;
// Keep the relocated image clear of v86's multiboot entry at 1 MiB while
// avoiding the original PE image base's 256 MiB address-space hole.
const DEFAULT_LOAD_ADDRESS = 2 * 1024 * 1024;
const STACK_SIZE = 64 * 1024;
const RETURN_GUARD_SIZE = 1024 * 1024;
const RETURN_SLED_SIZE = 512 * 1024;
const PE_CACHE = new WeakMap<ArrayBuffer, ReturnType<typeof parsePE>>();

function inspectPE(file: ArrayBuffer): ReturnType<typeof parsePE> {
  const cached = PE_CACHE.get(file);
  if (cached) return cached;
  const pe = parsePE(file);
  PE_CACHE.set(file, pe);
  return pe;
}

const NATIVE_HOOK_MAP: Readonly<Record<string, number>> = {
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

export class AquesTalk {
  readonly #dllImage: Uint8Array;
  readonly #writableSections: readonly {
    address: number;
    bytes: Uint8Array;
    zeroAddress: number;
    zeroSize: number;
  }[];
  readonly #emu;

  #baseAddress = 0;
  #aquesTalk_SyntheAddress = 0;
  #adjustFdivTargetAddress = 0;
  #returnAddress = 0;
  #stackTop = 0;

  readonly HEAP_ADDRESS: number;
  readonly HEAP_LENGTH: number;
  #heap: Heap = null as unknown as Heap;

  constructor(
    file: ArrayBuffer,
    emu: V86Emu,
    options: Pick<Options, "heapSize"> = {}
  ) {
    const pe = inspectPE(file);
    const heapSize = options.heapSize ?? DEFAULT_HEAP_SIZE;
    const loadAddress =
      pe.baseRelocationOffsets.length > 0
        ? DEFAULT_LOAD_ADDRESS
        : pe.baseAddress;
    if (!Number.isSafeInteger(heapSize) || heapSize <= 0) {
      throw new RangeError(`invalid heap size: ${heapSize}`);
    }
    this.#dllImage = new Uint8Array(file).slice();
    this.#emu = emu;
    this.#baseAddress = loadAddress;

    if (loadAddress !== pe.baseAddress) {
      const delta = loadAddress - pe.baseAddress;
      const imageView = new DataView(
        this.#dllImage.buffer,
        this.#dllImage.byteOffset,
        this.#dllImage.byteLength
      );
      for (const fileOffset of pe.baseRelocationOffsets) {
        imageView.setUint32(
          fileOffset,
          imageView.getUint32(fileOffset, true) + delta,
          true
        );
      }
    }

    this.#writableSections = pe.writableSections.map(section => {
      const rawSize = Math.min(section.rawSize, section.virtualSize);
      return {
        address: loadAddress + section.virtualAddress,
        bytes: this.#dllImage.subarray(
          section.pointerToRawData,
          section.pointerToRawData + rawSize
        ),
        zeroAddress: loadAddress + section.virtualAddress + rawSize,
        zeroSize: Math.max(0, section.virtualSize - rawSize),
      };
    });
    this.HEAP_ADDRESS = align_to_0x1000(loadAddress + pe.imageSize);
    this.HEAP_LENGTH = heapSize;
    this.#stackTop = this.HEAP_ADDRESS + heapSize + STACK_SIZE;

    emu.assert_memory_range(loadAddress, this.#dllImage.byteLength);
    emu.assert_memory_range(
      this.HEAP_ADDRESS,
      this.HEAP_LENGTH + STACK_SIZE
    );
    this.#init(pe);
  }

  #reset_esp() {
    reg_write_uint32(this.#emu, REG_ESP, this.#stackTop);
  }

  #init(pe: ReturnType<typeof parsePE>) {
    const emu = this.#emu;

    this.#aquesTalk_SyntheAddress = this.#baseAddress + pe.aquesTalkSyntheRVA;
    this.#adjustFdivTargetAddress = pe.adjustFdivTarget;

    this.#heap = new Heap(emu, this.HEAP_ADDRESS, this.HEAP_LENGTH);
    const nativeCodeAddress = this.#heap.set_mem_value(emu, NATIVE_CLIB_BIN);
    // Keep dynamic allocations 1 MiB away from executable helper code. v86's
    // JIT executes beyond the OUT stop instruction. Keep a 512 KiB NOP sled:
    // 256 KiB corrupts warmed output, while this retains a 2x safety margin.
    this.#returnAddress = this.#heap.allocate(RETURN_GUARD_SIZE);
    emu.mem_fill(this.#returnAddress, RETURN_SLED_SIZE, NOP);
    this.#heap.preserve_allocations();

    const dllView = new DataView(
      this.#dllImage.buffer,
      this.#dllImage.byteOffset,
      this.#dllImage.byteLength
    );
    for (const [name, offset] of Object.entries(NATIVE_HOOK_MAP)) {
      const info = pe.iatHooks[name];
      if (info) dllView.setUint32(info.rva, nativeCodeAddress + offset, true);
    }
    emu.mem_write(this.#baseAddress, this.#dllImage);
    this.#reset_esp();

    const hookMap: { [key: string]: (emu: V86Emu, ...args: any[]) => void } = {
      malloc: malloc_hook,
      free: free_hook,
    };

    for (const [name, info] of Object.entries(pe.iatHooks)) {
      if (hookMap[name]) {
        // We hook at the info.target address which is the unlinked address value from IAT.
        // The DLL code jumps to this address when calling imports.
        hook_lib_call(
          emu,
          info.target,
          hookMap[name],
          name === "malloc"
            ? (hookEmu: V86Emu, size: number) =>
                this.#heap.allocate_zeroed(hookEmu, size)
            : undefined
        );
      }
    }

    if (this.#adjustFdivTargetAddress) {
      emu.mem_write_uint32(this.#adjustFdivTargetAddress, 0);
    }
  }

  #reset() {
    this.#heap.reset_allocations();
    reg_write_uint32(this.#emu, REG_EAX, 0);
    this.#reset_esp();
  }

  #reset_writable_sections() {
    for (const section of this.#writableSections) {
      this.#emu.mem_write(section.address, section.bytes);
      if (section.zeroSize > 0) {
        this.#emu.mem_clear(section.zeroAddress, section.zeroSize);
      }
    }
  }

  run(koe: string, speed: number = 100): Uint8Array {
    const emu = this.#emu;

    // Reset CPU registers and segments before starting a new run
    emu.reset_cpu();
    this.#reset();

    try {
      // Only mutable PE sections can hold per-run global state. Reloading the
      // executable and read-only sections copied ~100 KiB unnecessarily.
      this.#reset_writable_sections();
      // Reset _adjust_fdiv and other low-memory state
      if (this.#adjustFdivTargetAddress) {
        emu.mem_write_uint32(this.#adjustFdivTargetAddress, 0);
      }

      const size = this.#heap.allocate_zeroed(emu, 4);
      const sjis = convert_sjis(koe);
      const koeAddress = this.#heap.allocate(sjis.byteLength + 1);
      emu.mem_write(koeAddress, sjis);
      emu.mem_clear(koeAddress + sjis.byteLength, 1);

      push(emu, size);
      push(emu, speed);
      push(emu, koeAddress);

      emu.set_eip(this.#returnAddress);
      call(emu, this.#aquesTalk_SyntheAddress);

      try {
        emu.emu_start(emu.get_eip(), this.#returnAddress);
      } catch (error) {
        console.error(error);
        console.error(`error at: EIP: `, emu.get_eip().toString(16));
        console.error(
          `error at: ESP:`,
          reg_read_uint32(emu, REG_ESP).toString(16)
        );
        throw error;
      }

      const sizeValue = emu.mem_read_uint32(size);
      const returnValue = reg_read_uint32(emu, REG_EAX);
      if (returnValue === 0) {
        throw new Error(`AquesTalk_Synthe error. ERROR CODE: ${sizeValue}`);
      }
      return emu.mem_read(returnValue, sizeValue);
    } finally {
      this.#reset();
    }
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
  const { baseUrl, ...loadOptions } = options;
  const zipPath = baseUrl
    ? new URL(VOICE_MAP[voice].zip.pathname.split("/").pop()!, baseUrl)
        .href
    : zip.href;

  let wasmPath =
    loadOptions.wasmPath ??
    (baseUrl ? new URL("v86.wasm", baseUrl).href : WASM_URL.href);

  // Convert to local path if Node.js to avoid fetch/URL issues in v86
  if (
    typeof process !== "undefined" &&
    process.versions &&
    process.versions.node &&
    wasmPath.startsWith("file://")
  ) {
    const { fileURLToPath } = await import("url");
    wasmPath = fileURLToPath(wasmPath);
  }

  return loadAquesTalk(zipPath, dll, { ...loadOptions, wasmPath });
}

async function getData(url: string | URL): Promise<ArrayBuffer | Uint8Array> {
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
    return fs.readFile(filePath);
  }
  const response = await fetch(urlStr);
  if (!response.ok) {
    throw new Error(`Failed to fetch ${urlStr}: ${response.status}`);
  }
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

  const pe = inspectPE(dllfile);
  const heapSize = options.heapSize ?? DEFAULT_HEAP_SIZE;
  const loadAddress =
    pe.baseRelocationOffsets.length > 0 ? DEFAULT_LOAD_ADDRESS : pe.baseAddress;
  if (!Number.isSafeInteger(heapSize) || heapSize <= 0) {
    throw new RangeError(`invalid heap size: ${heapSize}`);
  }
  const minimumMemorySize = align_to_0x1000(
    align_to_0x1000(loadAddress + pe.imageSize) + heapSize + STACK_SIZE
  );
  const memorySize = options.memorySize ?? minimumMemorySize;
  if (
    !Number.isSafeInteger(memorySize) ||
    memorySize <= 0 ||
    memorySize > 0xffff_ffff
  ) {
    throw new RangeError(`invalid memory size: ${memorySize}`);
  }
  if (memorySize < minimumMemorySize) {
    throw new RangeError(
      `memory size ${memorySize} is smaller than the required ${minimumMemorySize} bytes`
    );
  }

  const emu = new V86Emu();
  try {
    await emu.init({ ...options, memorySize });
    return new AquesTalk(dllfile, emu, {
      heapSize,
    });
  } catch (error) {
    await emu.destroy();
    throw error;
  }
}
