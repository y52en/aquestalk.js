import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";

async function main() {
  // Polyfill browser environment for unicorn-x86.min.js
  const mockWindow: any = {
    navigator: { userAgent: "Node" },
    location: { href: "http://localhost/" },
    performance: performance,
    console: console,
    ArrayBuffer: ArrayBuffer,
    Uint8Array: Uint8Array,
    DataView: DataView,
    Uint32Array: Uint32Array,
    Int32Array: Int32Array,
    TextEncoder: TextEncoder,
    TextDecoder: TextDecoder,
    addEventListener: () => {},
    removeEventListener: () => {},
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
  };
  mockWindow.self = mockWindow;
  mockWindow.window = mockWindow;
  mockWindow.document = {
    currentScript: { src: "http://localhost/unicorn-x86.min.js" },
    createElement: () => ({})
  };

  console.log("Loading unicorn-x86.min.js via VM...");
  const unicornCode = fs.readFileSync(path.join(__dirname, "../docs-src/public/unicorn-x86.min.js"), "utf8");
  
  const vm = require("vm");
  const context = vm.createContext(mockWindow);
  vm.runInContext(unicornCode, context);

  // After runInContext, uc should be available in the context
  const uc = context.uc;
  if (!uc) {
    console.error("Failed to load unicorn into context.uc");
    process.exit(1);
  }
  (global as any).window = context;
  (global as any).uc = uc;

  // AquesTalk on master uses 'uc' from global/window
  const { loadAquesTalk } = await import("../src/index");

  // Mock fetch for loadAquesTalk
  (global as any).fetch = async (url: string) => {
    const filePath = path.join(__dirname, "..", "docs-src", "public", url.replace(/^\.\//, ""));
    const buffer = fs.readFileSync(filePath);
    return {
      arrayBuffer: async () => buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)
    } as any;
  };

  console.log("Initializing AquesTalk (Unicorn)...");
  const aq = await loadAquesTalk("./f1.zip", "f1/AquesTalk.dll");

  const testText = "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほ、あいうえおかきくけこさしすせそ"; // Same text as v86

  // Warm up
  console.log("Warming up...");
  for (let i = 0; i < 5; i++) {
    await aq.run(testText);
  }

  const iterations = 10;
  console.log(`Running benchmark (${iterations} iterations)...`);
  
  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await aq.run(testText);
    const end = performance.now();
    times.push(end - start);
    console.log(`Iteration ${i + 1}: ${(end - start).toFixed(2)}ms`);
  }

  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  const min = Math.min(...times);
  const max = Math.max(...times);

  console.log(`=== Benchmark Results (Unicorn.js) ===`);
  console.log(`Average: ${avg.toFixed(2)}ms`);
  console.log(`Min:     ${min.toFixed(2)}ms`);
  console.log(`Max:     ${max.toFixed(2)}ms`);
}

main().catch(console.error);
