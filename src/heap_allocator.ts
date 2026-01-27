export class Allocator {
    private uc: any;
    private start: number;
    private offset: number;

    constructor(uc: any, start: number) {
        this.uc = uc;
        this.start = start;
        this.offset = 0;
    }

    alloc(size: number): number {
        const addr = this.start + this.offset;
        this.offset += size;
        // Align to 4 bytes
        if (this.offset % 4 !== 0) {
            this.offset += 4 - (this.offset % 4);
        }
        return addr;
    }

    write(data: Uint8Array): number {
        const addr = this.alloc(data.length);
        this.uc.mem_write(addr, data);
        return addr;
    }
}
