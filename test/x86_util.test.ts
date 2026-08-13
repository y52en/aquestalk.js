import { describe, it, expect, beforeEach, vi } from "vitest";
import { push, pop, jmp, call, ret, get_arg } from "../src/x86_util";
import { V86Emu, REG_ESP } from "../src/v86_emu";

describe("x86_util", () => {
  let mockEmu: any;

  beforeEach(() => {
    mockEmu = {
      mem_write: vi.fn(),
      mem_read: vi.fn(),
      mem_write_uint32: vi.fn(),
      mem_read_uint32: vi.fn(),
      reg_read: vi.fn(),
      reg_write: vi.fn(),
      get_eip: vi.fn(),
      set_eip: vi.fn(),
    } as unknown as V86Emu;
  });

  describe("push", () => {
    it("should decrement ESP by 4 and write value to new ESP", () => {
      let esp = 0x1000;
      mockEmu.reg_read.mockImplementation((reg: number) => {
        if (reg === REG_ESP) return esp;
        return 0;
      });
      mockEmu.reg_write.mockImplementation((reg: number, val: number) => {
        if (reg === REG_ESP) esp = val;
      });

      push(mockEmu, 0x12345678);

      expect(mockEmu.reg_write).toHaveBeenCalledWith(REG_ESP, 0x0ffc);
      expect(mockEmu.mem_write_uint32).toHaveBeenCalledWith(0x0ffc, 0x12345678);
    });
  });

  describe("pop", () => {
    it("should read value from current ESP and increment ESP by 4", () => {
      let esp = 0x0ffc;
      mockEmu.reg_read.mockImplementation((reg: number) => {
        if (reg === REG_ESP) return esp;
        return 0;
      });
      mockEmu.reg_write.mockImplementation((reg: number, val: number) => {
        if (reg === REG_ESP) esp = val;
      });
      mockEmu.mem_read_uint32.mockReturnValue(0x12345678);

      const value = pop(mockEmu);

      expect(value).toBe(0x12345678);
      expect(mockEmu.mem_read_uint32).toHaveBeenCalledWith(0x0ffc);
      expect(mockEmu.reg_write).toHaveBeenCalledWith(REG_ESP, 0x1000);
    });
  });

  describe("jmp", () => {
    it("should set EIP to given address", () => {
      jmp(mockEmu, 0x2000);
      expect(mockEmu.set_eip).toHaveBeenCalledWith(0x2000);
    });
  });

  describe("call", () => {
    it("should push current EIP and set EIP to target address", () => {
      let esp = 0x3000;
      mockEmu.get_eip.mockReturnValue(0x1000);
      mockEmu.reg_read.mockImplementation((reg: number) => {
        if (reg === REG_ESP) return esp;
        return 0;
      });
      mockEmu.reg_write.mockImplementation((reg: number, val: number) => {
        if (reg === REG_ESP) esp = val;
      });

      call(mockEmu, 0x2000);

      expect(mockEmu.reg_write).toHaveBeenCalledWith(REG_ESP, 0x2ffc);
      expect(mockEmu.mem_write_uint32).toHaveBeenCalledWith(0x2ffc, 0x1000);
      expect(mockEmu.set_eip).toHaveBeenCalledWith(0x2000);
    });
  });

  describe("ret", () => {
    it("should pop target address from stack and set EIP", () => {
      let esp = 0x2ffc;
      mockEmu.reg_read.mockImplementation((reg: number) => {
        if (reg === REG_ESP) return esp;
        return 0;
      });
      mockEmu.reg_write.mockImplementation((reg: number, val: number) => {
        if (reg === REG_ESP) esp = val;
      });
      mockEmu.mem_read_uint32.mockReturnValue(0x2000);

      ret(mockEmu);

      expect(mockEmu.reg_write).toHaveBeenCalledWith(REG_ESP, 0x3000);
      expect(mockEmu.set_eip).toHaveBeenCalledWith(0x2000);
    });
  });

  describe("get_arg", () => {
    it("should read from ESP + 4 * (1 + num)", () => {
      mockEmu.reg_read.mockImplementation((reg: number) => {
        if (reg === REG_ESP) return 0x1000;
        return 0;
      });
      mockEmu.mem_read_uint32.mockImplementation((addr: number) => {
        if (addr === 0x1004) return 0xaaaa;
        if (addr === 0x1008) return 0xbbbb;
        return 0;
      });

      const arg0 = get_arg(mockEmu, 0);
      const arg1 = get_arg(mockEmu, 1);

      expect(arg0).toBe(0xaaaa);
      expect(arg1).toBe(0xbbbb);
      expect(mockEmu.mem_read_uint32).toHaveBeenCalledWith(0x1004);
      expect(mockEmu.mem_read_uint32).toHaveBeenCalledWith(0x1008);
    });
  });
});
