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

// Simulate some usage
heap.heap_used = 1024; // Used 1KB out of 10MB

console.time("clear_heap baseline");
for (let i = 0; i < ITERATIONS; i++) {
    heap.clear_heap(mockEmu);
}
console.timeEnd("clear_heap baseline");
