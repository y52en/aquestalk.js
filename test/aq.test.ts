import { afterAll, beforeAll, describe, expect, it } from "vitest";
import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { V86Emu } from "../src/v86_emu.js";
import { AquesTalk, load } from "../src/index.js";
import { fileURLToPath } from "url";
import { createHash } from "crypto";

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
    await emu.init({ wasmPath });

    // Create AquesTalk instance once
    aq = new AquesTalk(dllFile, emu);
  }, 30000); // 30s timeout for init

  afterAll(async () => {
    await aq.destroy();
  });

  it("should synthesize speech and return a WAV file", () => {
    const result = aq.run("ゆっくりしていってね");
    
    expect(result).toBeDefined();
    expect(result.length).toBeGreaterThan(44); // MIN WAV header size
    
    // Check RIFF header
    const header = String.fromCharCode(...result.slice(0, 4));
    expect(header).toBe("RIFF");
    expect(createHash("sha256").update(result).digest("hex")).toBe(
      "300500de9385cb49d8ade0a2cbf6e73d8615232bd4742107a28f4f4a9d8f367f"
    );
  }, 30000);

  it("should handle multiple calls", () => {
    const result1 = aq.run("こんにちわ");
    const result2 = aq.run("こんばんわ");
    
    expect(result1).toBeDefined();
    expect(result2).toBeDefined();
    expect(result1.length).not.toBe(result2.length);
  }, 30000);

  it("should preserve output at the slow, maximum-length boundary", () => {
    const input =
      "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわをん、"
        .repeat(4)
        .slice(0, 128);
    const result = aq.run(input, 50);

    expect(createHash("sha256").update(result).digest("hex")).toBe(
      "82b6b88a2e047be279d373eb5606725f70fed16a509c0076b1fdc9c8a30c3f9c"
    );
  }, 30000);

  it("should stay deterministic as v86 JIT blocks warm up", async () => {
    const cases = [
      { input: "ゆっくりしていってね", speed: 100 },
      {
        input:
          "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほ、あいうえおかきくけこさしすせそ",
        speed: 100,
      },
    ];
    for (const benchmarkCase of cases) {
      for (let iteration = 0; iteration < 8; iteration += 1) {
        aq.run(benchmarkCase.input, benchmarkCase.speed);
        await new Promise(resolve => setImmediate(resolve));
      }
    }

    const longInput =
      "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわをん、".repeat(
        2
      );
    for (let iteration = 0; iteration < 8; iteration += 1) {
      const result = aq.run(longInput, 50);
      expect(createHash("sha256").update(result).digest("hex")).toBe(
        "507322572fdff071c2a4a3c2b3f598060309f06f647c3f6d4a48c6122e470085"
      );
      await new Promise(resolve => setImmediate(resolve));
    }
  }, 30000);

  it("should throw an error on invalid input", () => {
    expect(() => {
      aq.run("invalid_string_12345!@#$%");
    }).toThrow(/AquesTalk_Synthe error\. ERROR CODE: \d+/);

    const recovered = aq.run("こんにちわ");
    expect(String.fromCharCode(...recovered.slice(0, 4))).toBe("RIFF");
  }, 30000);
});

describe("load", () => {
  it("uses the automatically sized relocated memory layout", async () => {
    const options = {};
    const loaded = await load("f1", options);
    try {
      const result = loaded.run("ゆっくりしていってね");
      expect(createHash("sha256").update(result).digest("hex")).toBe(
        "300500de9385cb49d8ade0a2cbf6e73d8615232bd4742107a28f4f4a9d8f367f"
      );
      expect(options).toEqual({});
    } finally {
      await loaded.destroy();
    }
  }, 30000);

  it("recovers when input allocation exceeds a custom heap", async () => {
    const loaded = await load("f1", { heapSize: 1280 * 1024 });
    try {
      expect(() => loaded.run("あ".repeat(200_000))).toThrow("heap over");

      const recovered = loaded.run("こんにちわ");
      expect(String.fromCharCode(...recovered.slice(0, 4))).toBe("RIFF");
    } finally {
      await loaded.destroy();
    }
  }, 30000);
});
