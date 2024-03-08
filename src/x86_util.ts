import { reg_read_uint32, reg_write_uint32 } from "./unicorn_util";
import { from_bytes_uint32, to_bytes_uint32 } from "./util";

const uc = window.uc;

export function push(mu: Uc, value: number) {
  reg_write_uint32(mu, uc.X86_REG_ESP, reg_read_uint32(mu, uc.X86_REG_ESP) - 4);
  mu.mem_write(reg_read_uint32(mu, uc.X86_REG_ESP), to_bytes_uint32(value));
}

export function pop(mu: Uc): number {
  const value = from_bytes_uint32(
    mu.mem_read(reg_read_uint32(mu, uc.X86_REG_ESP), 4)
  );
  reg_write_uint32(mu, uc.X86_REG_ESP, reg_read_uint32(mu, uc.X86_REG_ESP) + 4);
  return value;
}

export function jmp(mu: Uc, address: number) {
  reg_write_uint32(mu, uc.X86_REG_EIP, address);
}

export function call(mu: Uc, address: number) {
  push(mu, reg_read_uint32(mu, uc.X86_REG_EIP));
  jmp(mu, address);
}

export function ret(mu: Uc) {
  const ret_address = pop(mu);
  jmp(mu, ret_address);
}

export function get_arg(mu: Uc, num: number): number {
  return from_bytes_uint32(
    mu.mem_read(reg_read_uint32(mu, uc.X86_REG_ESP) + 4 * (1 + num), 4)
  );
}
