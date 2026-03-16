import { V86Emu, REG_EAX } from "./v86_emu.js";
import { reg_write_uint32 } from "./emu_util.js";
import { get_arg, ret } from "./x86_util.js";

export function malloc_hook(emu: V86Emu, ...args: unknown[]) {
  const arg0 = get_arg(emu, 0);

  const last_callback_arg = args[args.length - 1];
  if (typeof last_callback_arg != "function") {
    throw new Error("malloc_hook: last argument must be a function");
  }
  // set_mem_value
  const address = last_callback_arg(emu, new Uint8Array(arg0).fill(0));

  reg_write_uint32(emu, REG_EAX, address);
  ret(emu);
}

export function strncmp_hook(emu: V86Emu, ..._args: unknown[]) {
  const str0 = get_arg(emu, 0);
  const str1 = get_arg(emu, 1);
  const max_len = get_arg(emu, 2);

  let result = 0;
  let offset = 0;
  outer: while (offset < max_len) {
    const page_limit0 = 4096 - ((str0 + offset) % 4096);
    const page_limit1 = 4096 - ((str1 + offset) % 4096);
    let to_read = Math.min(256, max_len - offset, page_limit0, page_limit1);

    const chunk0 = emu.mem_read(str0 + offset, to_read);
    const chunk1 = emu.mem_read(str1 + offset, to_read);

    const read_len = Math.min(chunk0.length, chunk1.length);
    if (read_len === 0) break;

    for (let i = 0; i < read_len; i++) {
      if (chunk0[i] !== chunk1[i]) {
        result = chunk0[i] - chunk1[i];
        break outer;
      }
    }
    offset += read_len;
  }

  reg_write_uint32(emu, REG_EAX, result);
  ret(emu);
}

export function strncpy_hook(emu: V86Emu, ..._args: unknown[]) {
  const dest = get_arg(emu, 0);
  const src = get_arg(emu, 1);
  const count = get_arg(emu, 2);

  emu.mem_write(dest, emu.mem_read(src, count));
  reg_write_uint32(emu, REG_EAX, dest);
  ret(emu);
}

export function free_hook(emu: V86Emu, ..._args: unknown[]) {
  ret(emu);
}

export function strtok_hook(emu: V86Emu, ..._args: unknown[]) {
  // strtok(str, delim) - simplified: return NULL
  reg_write_uint32(emu, REG_EAX, 0);
  ret(emu);
}

export function strchr_hook(emu: V86Emu, ..._args: unknown[]) {
  // strchr(str, ch)
  const str = get_arg(emu, 0);
  const ch = get_arg(emu, 1) & 0xff;

  let offset = 0;
  outer: while (true) {
    const page_limit = 4096 - ((str + offset) % 4096);
    const to_read = Math.min(256, page_limit);
    const chunk = emu.mem_read(str + offset, to_read);

    if (chunk.length === 0) break;

    for (let i = 0; i < chunk.length; i++) {
      const byte = chunk[i];
      if (byte === ch) {
        reg_write_uint32(emu, REG_EAX, str + offset + i);
        ret(emu);
        return;
      }
      if (byte === 0) break outer;
    }
    offset += chunk.length;
  }

  reg_write_uint32(emu, REG_EAX, 0);
  ret(emu);
}

export function stricmp_hook(emu: V86Emu, ..._args: unknown[]) {
  // _stricmp(str1, str2) - case-insensitive compare
  const str0 = get_arg(emu, 0);
  const str1 = get_arg(emu, 1);

  let offset = 0;
  outer: while (true) {
    const page_limit0 = 4096 - ((str0 + offset) % 4096);
    const page_limit1 = 4096 - ((str1 + offset) % 4096);
    let to_read = Math.min(256, page_limit0, page_limit1);

    const chunk0 = emu.mem_read(str0 + offset, to_read);
    const chunk1 = emu.mem_read(str1 + offset, to_read);

    const read_len = Math.min(chunk0.length, chunk1.length);
    if (read_len === 0) break;

    for (let i = 0; i < read_len; i++) {
      let a = chunk0[i];
      let b = chunk1[i];
      // To lowercase
      if (a >= 0x41 && a <= 0x5a) a += 0x20;
      if (b >= 0x41 && b <= 0x5a) b += 0x20;
      if (a !== b) {
        reg_write_uint32(emu, REG_EAX, a - b);
        ret(emu);
        return;
      }
      if (a === 0) break outer;
    }
    offset += read_len;
  }

  reg_write_uint32(emu, REG_EAX, 0);
  ret(emu);
}

export function initterm_hook(emu: V86Emu, ..._args: unknown[]) {
  // _initterm(start, end) - calls function pointers between start and end
  // We skip this since there's nothing to initialize
  ret(emu);
}

export function adjust_fdiv_hook(emu: V86Emu, ..._args: unknown[]) {
  // _adjust_fdiv - checks for Pentium FDIV bug, return 0 (no bug)
  reg_write_uint32(emu, REG_EAX, 0);
  ret(emu);
}

export function cxx_frame_handler_hook(emu: V86Emu, ..._args: unknown[]) {
  // __CxxFrameHandler - C++ exception handler
  // We don't support exceptions, just return
  reg_write_uint32(emu, REG_EAX, 0);
  ret(emu);
}

export function disable_thread_library_calls_hook(
  emu: V86Emu,
  ..._args: unknown[]
) {
  // DisableThreadLibraryCalls - no-op in emulation
  reg_write_uint32(emu, REG_EAX, 1); // return TRUE
  ret(emu);
}
