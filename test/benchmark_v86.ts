import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { V86Emu } from "../src/v86_emu";
import { AquesTalk } from "../src/index";

async function main() {
  const zipPath = path.join(__dirname, "..", "docs", "f1.zip");
  const zipBuf = fs.readFileSync(zipPath);
  const zip = new JSZip();
  const zipRoot = await zip.loadAsync(zipBuf);
  const dllFile = await zipRoot.files["f1/AquesTalk.dll"].async("arraybuffer");

  const emu = new V86Emu();
  const wasmPath = path.join(__dirname, "..", "node_modules", "v86", "build", "v86.wasm");
  await emu.init({ wasmPath, memorySize: 1024 * 1024 * 1024 });

  const aq = new AquesTalk(dllFile, emu);

  const testText = "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほ、あいうえおかきくけこさしすせそ"; // Long Hiragana
  
  // Warm up
  console.log("Warming up...");
  for (let i = 0; i < 5; i++) {
    aq.run(testText);
  }

  const iterations = 10;
  console.log(`Running benchmark (${iterations} iterations)...`);
  
  const times: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    aq.run(testText);
    const end = performance.now();
    times.push(end - start);
    console.log(`Iteration ${i + 1}: ${(end - start).toFixed(2)}ms`);
  }

  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  const min = Math.min(...times);
  const max = Math.max(...times);

  console.log(`=== Benchmark Results (v86) ===`);
  console.log(`Average: ${avg.toFixed(2)}ms`);
  console.log(`Min:     ${min.toFixed(2)}ms`);
  console.log(`Max:     ${max.toFixed(2)}ms`);
}

main().catch(console.error);
