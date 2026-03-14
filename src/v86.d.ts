declare module "v86" {
  export class V86 {
    constructor(options: {
      wasm_path?: string;
      memory_size?: number;
      vga_memory_size?: number;
      autostart?: boolean;
      bios?: { url?: string; buffer?: ArrayBuffer };
      vga_bios?: { url?: string; buffer?: ArrayBuffer };
      multiboot?: { url?: string; buffer?: ArrayBuffer };
      screen_container?: HTMLElement | null;
      [key: string]: any;
    });

    v86: {
      cpu: any;
      run(): void;
      stop(): void;
    };

    cpu_exception_hook: (n: number) => boolean | void;

    run(): Promise<void>;
    stop(): Promise<void>;
    destroy(): Promise<void>;
    add_listener(event: string, callback: (...args: any[]) => void): void;
    remove_listener(event: string, callback: (...args: any[]) => void): void;
    read_memory(offset: number, length: number): Uint8Array;
    write_memory(blob: Uint8Array, offset: number): void;
    save_state(): Promise<ArrayBuffer>;
    restore_state(state: ArrayBuffer): Promise<void>;
  }
}
