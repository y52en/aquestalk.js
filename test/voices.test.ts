import { describe, it, expect, beforeAll } from "vitest";
import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { V86Emu } from "../src/v86_emu";
import { AquesTalk } from "../src/index";

describe("AquesTalk Multi-Voice Support", () => {
  const voices = [
    { name: "f1", zip: "f1.zip", dll: "f1/AquesTalk.dll" },
    { name: "f2", zip: "f2.zip", dll: "f2/AquesTalk.dll" },
  ];

  for (const voice of voices) {
    it(`should synthesize speech with ${voice.name} voice`, async () => {
      // Load zip file
      const zipPath = path.join(__dirname, "..", "docs-src", "public", voice.zip);
      const zipBuf = fs.readFileSync(zipPath);
      const zip = new JSZip();
      const zipRoot = await zip.loadAsync(zipBuf);
      const dllFile = await zipRoot.files[voice.dll].async("arraybuffer");

      // Initialize v86 emulator with 1GB memory
      const emu = new V86Emu();
      const wasmPath = path.join(__dirname, "..", "node_modules", "v86", "build", "v86.wasm");
      await emu.init({ wasmPath, memorySize: 1024 * 1024 * 1024 });

      const aq = new AquesTalk(dllFile, emu);
      const result = aq.run("こんにちわ");
      
      expect(result).toBeDefined();
      expect(result.length).toBeGreaterThan(44); // MIN WAV header size
      
      // Check RIFF header
      const header = String.fromCharCode(...result.slice(0, 4));
      expect(header).toBe("RIFF");
    }, 60000); // 60s timeout for each voice
  }
});
