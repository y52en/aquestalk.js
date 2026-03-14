/**
 * Test script: Verify AquesTalk v86 emulation works correctly.
 * Run with: npx ts-node test/test_v86.ts
 */
import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { V86Emu } from "../src/v86_emu";
import { AquesTalk } from "../src/index";

async function main() {
  console.log("=== AquesTalk v86 Test ===");
  console.log("Loading DLL from zip...");

  // Load zip file
  const zipPath = path.join(__dirname, "..", "docs", "f1.zip");
  const zipBuf = fs.readFileSync(zipPath);
  const zip = new JSZip();
  const zipRoot = await zip.loadAsync(zipBuf);
  const dllFile = await zipRoot.files["f1/AquesTalk.dll"].async("arraybuffer");
  console.log(`DLL size: ${dllFile.byteLength} bytes`);

  // Initialize v86 emulator
  console.log("Initializing v86 emulator...");
  const startInit = performance.now();
  const emu = new V86Emu();
  const wasmPath = path.join(__dirname, "..", "node_modules", "v86", "build", "v86.wasm");
  // Need 1GB memory to accommodate BASE_ADDRESS (0x10000000) and HEAP (0x20000000)
  await emu.init({ wasmPath, memorySize: 1024 * 1024 * 1024 });
  const initTime = performance.now() - startInit;
  console.log(`v86 initialized in ${initTime.toFixed(1)}ms`);

  // Create AquesTalk instance
  console.log("Creating AquesTalk instance...");
  const aq = new AquesTalk(dllFile, emu);

  // Run TTS synthesis
  const testText = "こんにちわ、せかい";
  console.log(`Synthesizing: "${testText}"`);

  const startSynth = performance.now();
  const result = aq.run(testText);
  const synthTime = performance.now() - startSynth;

  console.log(`Synthesis completed in ${synthTime.toFixed(1)}ms`);
  console.log(`Output size: ${result.length} bytes`);

  // Verify output is a valid WAV file (starts with "RIFF")
  const header = String.fromCharCode(...result.slice(0, 4));
  if (header === "RIFF") {
    console.log("✅ Output is a valid WAV file (RIFF header detected)");
  } else {
    console.error(
      `❌ Output does not appear to be a valid WAV file. Header: ${header}`
    );
    process.exit(1);
  }

  // Save output for inspection
  const outPath = path.join(__dirname, "output.wav");
  fs.writeFileSync(outPath, result);
  console.log(`Output saved to: ${outPath}`);

  console.log("\n=== Test Passed ===");
}

main().catch((e) => {
  console.error("Test failed:", e);
  process.exit(1);
});
