import { V86Emu } from "./src/v86_emu.js";
import { Heap } from "./src/emu_util.js";

// Mock minimal V86Emu interface needed for Heap
const mockEmu = {
    mem_write: () => {},
} as unknown as V86Emu;

const ITERATIONS = 10000;
// Test with a reasonably large heap, say 10MB
const HEAP_LEN = 10 * 1024 * 1024;

const heap = new Heap(mockEmu, 0, HEAP_LEN);

console.time("clear_heap optimized");
for (let i = 0; i < ITERATIONS; i++) {
    heap.heap_used = 1024; // Used 1KB out of 10MB
    if (heap.heap_used > 0) {
        mockEmu.mem_write(heap.heap_addr, new Uint8Array(heap.heap_used));
        heap.heap_used = 0;
    }
}
console.timeEnd("clear_heap optimized");
