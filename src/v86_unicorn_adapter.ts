
// @ts-ignore
import { V86 } from './lib/libv86_debug.mjs';
import * as path from 'path';

export const UC_X86_REG_EAX = 0;
export const UC_X86_REG_ECX = 1;
export const UC_X86_REG_EDX = 2;
export const UC_X86_REG_EBX = 3;
export const UC_X86_REG_ESP = 4;
export const UC_X86_REG_EBP = 5;
export const UC_X86_REG_ESI = 6;
export const UC_X86_REG_EDI = 7;
export const UC_X86_REG_EIP = 8;
export const UC_X86_REG_EFLAGS = 9;

export const UC_HOOK_CODE = 1;
export const UC_HOOK_BLOCK = 2;

export class V86UnicornAdapter {
    private v86: any;
    private cpu: any;
    private memory: Uint8Array | null = null;
    private hooks: Map<number, (uc: V86UnicornAdapter, address: number, size: number, user_data: any) => void>;
    private hook_data: Map<number, any>;
    private mapped_memory: Map<number, {size: number, perms: number}>;

    constructor() {
        // v86.wasm is still in node_modules, bios in test (fixtures).
        // In production, these paths should probably be configurable or bundled differently.
        const wasmPath = path.join(process.cwd(), 'node_modules/v86/build/v86.wasm');
        const biosPath = path.join(process.cwd(), 'test/bios.bin');
        const vgaPath = path.join(process.cwd(), 'test/vga_bios.bin');

        this.v86 = new V86({
            wasm_path: wasmPath,
            memory_size: 64 * 1024 * 1024,
            vga_memory_size: 2 * 1024 * 1024,
            bios: { url: biosPath },
            vga_bios: { url: vgaPath },
            network_relay_url: '',
            autostart: false,
            disable_keyboard: true,
            disable_mouse: true,
            disable_speaker: true
        });

        this.hooks = new Map();
        this.hook_data = new Map();
        this.mapped_memory = new Map();
    }

    async initialize() {
        return new Promise<void>((resolve, reject) => {
            let resolved = false;
            this.v86.add_listener("emulator-ready", () => {
                if (resolved) return;
                resolved = true;

                // Fallback search for cpu object
                if (this.v86.cpu) {
                    this.cpu = this.v86.cpu;
                } else if (this.v86.v86 && this.v86.v86.cpu) {
                    this.cpu = this.v86.v86.cpu;
                } else {
                     for (const key of Object.keys(this.v86)) {
                        const val = this.v86[key];
                        if (val && typeof val === 'object' && val.constructor && (val.constructor.name === 'O' || val.mem8)) {
                             this.cpu = val;
                             break;
                        }
                    }
                }

                if (!this.cpu) {
                    reject(new Error("CPU not found on V86 instance"));
                    return;
                }

                this.memory = this.cpu.mem8;

                this.initProtectedMode();
                resolve();
            });

            setTimeout(() => {
                if (!resolved) {
                    reject(new Error("Timeout waiting for emulator-ready"));
                }
            }, 5000);
        });
    }

    private initProtectedMode() {
        this.cpu.cr[0] |= 1;

        for (let i = 0; i < 6; i++) {
            this.cpu.segment_offsets[i] = 0;
            this.cpu.segment_limits[i] = 0xFFFFFFFF;
            this.cpu.segment_is_null[i] = 0;
            this.cpu.segment_access_bytes[i] = i === 0 ? 0x9A : 0x92;
        }

        this.cpu.instruction_pointer[0] = 0;
        this.cpu.reg32[UC_X86_REG_ESP] = this.cpu.memory_size[0] - 0x1000;
        this.cpu.is_32[0] = 1;
        this.cpu.stack_size_32[0] = 1;
    }

    mem_map(address: number, size: number, perms: number) {
        this.mapped_memory.set(address, {size, perms});
    }

    mem_write(address: number, data: Uint8Array) {
        if (!this.memory) throw new Error("Memory not initialized");
        this.memory.set(data, address);
    }

    mem_read(address: number, size: number): Uint8Array {
        if (!this.memory) throw new Error("Memory not initialized");
        return this.memory.slice(address, address + size);
    }

    reg_write(regid: number, value: number) {
        if (!this.cpu) throw new Error("CPU not initialized");
        if (regid === UC_X86_REG_EFLAGS) {
            this.cpu.flags[0] = value;
        } else if (regid === UC_X86_REG_EIP) {
            this.cpu.instruction_pointer[0] = value;
        } else {
            this.cpu.reg32[regid] = value;
        }
    }

    reg_read(regid: number): number {
        if (!this.cpu) throw new Error("CPU not initialized");
        if (regid === UC_X86_REG_EFLAGS) {
            return this.cpu.flags[0];
        } else if (regid === UC_X86_REG_EIP) {
            return this.cpu.instruction_pointer[0];
        } else {
            return this.cpu.reg32[regid];
        }
    }

    hook_add(type: number, callback: any, user_data: any, begin: number, end: number) {
        if (type === UC_HOOK_CODE) {
            if (begin === end || end === 0) {
                 this.hooks.set(begin, callback);
                 this.hook_data.set(begin, user_data);
                 // IMPORTANT: Write HLT (0xF4) to the address to stop execution
                 this.mem_write(begin, new Uint8Array([0xF4]));
            }
        }
    }

    async emu_start(begin: number, until: number, timeout: number, count: number) {
        if (!this.cpu) throw new Error("CPU not initialized");
        this.cpu.instruction_pointer[0] = begin;

        let steps = 0;
        const startTime = Date.now();

        try {
            while (true) {
                this.cpu.main_loop();

                const current_eip = this.cpu.instruction_pointer[0];

                if (this.cpu.in_hlt[0]) {
                    if (this.hooks.has(current_eip)) {
                        const cb = this.hooks.get(current_eip);
                        const ud = this.hook_data.get(current_eip);
                        if (cb) {
                            cb(this, current_eip, 1, ud);
                            this.cpu.in_hlt[0] = 0;
                        }
                    } else {
                        break;
                    }
                }

                if (current_eip === until) {
                    break;
                }

                if (timeout && (Date.now() - startTime > timeout)) {
                    throw new Error("Timeout");
                }

                if (count && steps >= count) {
                    break;
                }
                steps++;

                await new Promise(resolve => setTimeout(resolve, 0));
            }
        } catch (e) {
            throw e;
        }
    }

    emu_stop() {
    }
}
