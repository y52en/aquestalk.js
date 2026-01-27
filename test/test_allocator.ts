import { V86UnicornAdapter } from '../src/v86_unicorn_adapter.ts';
import { Allocator } from '../src/heap_allocator.ts';

async function main() {
    console.log("Starting Allocator Test");

    const adapter = new V86UnicornAdapter();
    await adapter.initialize();

    // Use 16MB address, well within 64MB limit
    const heapStart = 0x1000000;
    const allocator = new Allocator(adapter, heapStart);

    // Test Alloc
    const ptr1 = allocator.alloc(10);
    console.log(`Allocated 10 bytes at 0x${ptr1.toString(16)}`);
    if (ptr1 !== heapStart) throw new Error("Allocator pointer mismatch");

    const ptr2 = allocator.alloc(4);
    // 10 aligned to 4 bytes is 12. So next should be +12?
    // 10 % 4 = 2. 10 + (4-2) = 12.
    console.log(`Allocated 4 bytes at 0x${ptr2.toString(16)}`);
    if (ptr2 !== heapStart + 12) throw new Error(`Allocator alignment failed: Expected ${heapStart + 12}, got ${ptr2}`);

    // Test Write
    const data = new Uint8Array([1, 2, 3, 4]);
    const ptr3 = allocator.write(data);
    console.log(`Written 4 bytes at 0x${ptr3.toString(16)}`);

    const readBack = adapter.mem_read(ptr3, 4);
    if (readBack[0] !== 1 || readBack[3] !== 4) throw new Error("Allocator write failed");

    console.log("Allocator Test Passed");
}

main().catch(e => {
    console.error(e);
    process.exit(1);
});
