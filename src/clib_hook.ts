import { reg_write_uint32 } from "./unicorn_util";
import { get_arg, ret } from "./x86_util";

const uc = window.uc;
export function malloc_hook(mu: Uc, ...args: unknown[]) {
  const arg0 = get_arg(mu, 0);

  const last_callback_arg = args[args.length - 1];
  if (typeof last_callback_arg != "function") {
    throw new Error("malloc_hook: last argument must be a function");
  }
  // set_mem_value
  const address = last_callback_arg(mu, new Uint8Array(arg0).fill(0));

  reg_write_uint32(mu, uc.X86_REG_EAX, address);
  ret(mu);
}

export function strncmp_hook(mu: Uc, ..._args: unknown[]) {
  const str0 = get_arg(mu, 0);
  const str1 = get_arg(mu, 1);
  const max_len = get_arg(mu, 2);

  let result = 0;
  for (let i = 0; i < max_len; i++) {
    if (mu.mem_read(str0 + i, 1)[0] !== mu.mem_read(str1 + i, 1)[0]) {
      result = mu.mem_read(str0 + i, 1)[0] - mu.mem_read(str1 + i, 1)[0];
      break;
    }
  }

  reg_write_uint32(mu, uc.X86_REG_EAX, result);
  ret(mu);
}

export function strncpy_hook(mu: Uc, ..._args: unknown[]) {
  const dest = get_arg(mu, 0);
  const src = get_arg(mu, 1);
  const count = get_arg(mu, 2);

  mu.mem_write(dest, mu.mem_read(src, count));
  reg_write_uint32(mu, uc.X86_REG_EAX, dest);
  ret(mu);
}

export function free_hook(mu: Uc, ..._args: unknown[]) {
  // const _address = get_arg(mu, 0);
  ret(mu);
}
