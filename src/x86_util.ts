import { V86Emu, REG_ESP } from "./v86_emu.js";
import { reg_read_uint32, reg_write_uint32 } from "./emu_util.js";

export function push(emu: V86Emu, value: number) {
  const esp = reg_read_uint32(emu, REG_ESP) - 4;
  reg_write_uint32(emu, REG_ESP, esp);
  emu.mem_write_uint32(esp, value);
}

export function pop(emu: V86Emu): number {
  const esp = reg_read_uint32(emu, REG_ESP);
  const value = emu.mem_read_uint32(esp);
  reg_write_uint32(emu, REG_ESP, esp + 4);
  return value;
}

export function jmp(emu: V86Emu, address: number) {
  emu.set_eip(address);
}

export function call(emu: V86Emu, address: number) {
  push(emu, emu.get_eip());
  jmp(emu, address);
}

export function ret(emu: V86Emu) {
  jmp(emu, pop(emu));
}

export function get_arg(emu: V86Emu, num: number): number {
  return emu.mem_read_uint32(reg_read_uint32(emu, REG_ESP) + 4 * (1 + num));
}
