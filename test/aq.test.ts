import { describe, it, expect, beforeAll } from "vitest";
import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { V86Emu } from "../src/v86_emu.js";
import { AquesTalk } from "../src/index.js";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("AquesTalk Integration", () => {
  let dllFile: ArrayBuffer;
  let emu: V86Emu;
  let aq: AquesTalk;

  beforeAll(async () => {
    // Load zip file
    const zipPath = path.join(__dirname, "..", "voices", "f1.zip");
    const zipBuf = fs.readFileSync(zipPath);
    const zip = new JSZip();
    const zipRoot = await zip.loadAsync(zipBuf);
    dllFile = await zipRoot.files["f1/AquesTalk.dll"].async("arraybuffer");

    // Initialize v86 emulator
    emu = new V86Emu();
    const wasmPath = path.join(__dirname, "..", "voices", "v86.wasm");
    await emu.init({ wasmPath, memorySize: 1024 * 1024 * 1024 });

    // Create AquesTalk instance once
    aq = new AquesTalk(dllFile, emu);
  }, 30000); // 30s timeout for init

  it("should synthesize speech and return a WAV file", () => {
    const result = aq.run("こんにちわ");
    
    expect(result).toBeDefined();
    expect(result.length).toBeGreaterThan(44); // MIN WAV header size
    
    // Check RIFF header
    const header = String.fromCharCode(...result.slice(0, 4));
    expect(header).toBe("RIFF");
  }, 30000);

  it("should handle multiple calls", () => {
    const result1 = aq.run("こんにちわ");
    const result2 = aq.run("こんばんわ");
    
    expect(result1).toBeDefined();
    expect(result2).toBeDefined();
    expect(result1.length).not.toBe(result2.length);
  }, 30000);
});
