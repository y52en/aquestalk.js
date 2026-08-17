import { afterAll, beforeAll, describe, expect, it } from "vitest";
import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { V86Emu } from "../src/v86_emu.js";
import { AquesTalk, load } from "../src/index.js";
import { convert_sjis } from "../src/util.js";
import { fileURLToPath } from "url";
import { createHash } from "crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const LONG_INPUT_SEED =
  "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわをん、";

describe("AquesTalk Integration", () => {
  let dllFile: ArrayBuffer;
  let emu: V86Emu;
  let aq: AquesTalk;

  beforeAll(async () => {
    const zipPath = path.join(__dirname, "..", "voices", "f1.zip");
    const zipBuf = fs.readFileSync(zipPath);
    const zip = new JSZip();
    const zipRoot = await zip.loadAsync(zipBuf);
    dllFile = await zipRoot.files["f1/AquesTalk.dll"].async("arraybuffer");

    emu = new V86Emu();
    const wasmPath = path.join(__dirname, "..", "voices", "v86.wasm");
    await emu.init({ wasmPath });

    aq = new AquesTalk(dllFile, emu);
  }, 30000);

  afterAll(async () => {
    await aq.destroy();
  });

  it("should synthesize speech and return a WAV file", () => {
    const result = aq.run("ゆっくりしていってね");

    expect(result).toBeDefined();
    expect(result.length).toBeGreaterThan(44);

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

  it("should return WAV bytes independent from later guest-memory reuse", () => {
    const result1 = aq.run("こんにちわ");
    const snapshot = Uint8Array.from(result1);
    const hash = createHash("sha256").update(snapshot).digest("hex");

    // run() resets and reuses guest allocations. A previous return value must
    // remain owned by JS so callers do not need an extra .slice().
    aq.run("こんばんわ");
    aq.run("ゆっくりしていってね");

    expect(result1).toEqual(snapshot);
    expect(createHash("sha256").update(result1).digest("hex")).toBe(hash);
  }, 30000);

  it("should preserve output at the DLL's total input boundary", () => {
    const input = LONG_INPUT_SEED.repeat(50).slice(0, 2047);
    expect(convert_sjis(input)).toHaveLength(4094);

    const result = aq.run(input, 50);

    expect(createHash("sha256").update(result).digest("hex")).toBe(
      "29f14b427a88c9fbe669a4c442c22d3cd5e3c233d2105ac3667664f770e96a39"
    );
  }, 60000);

  it("should leave total and per-phrase length validation to the DLL", () => {
    const maximumPhrase = "あ".repeat(255);
    expect(String.fromCharCode(...aq.run(maximumPhrase, 300).slice(0, 4))).toBe(
      "RIFF"
    );
    expect(() => aq.run(`${maximumPhrase}あ`, 300)).toThrow(
      "AquesTalk_Synthe error. ERROR CODE: 102"
    );

    const overTotalLimit = LONG_INPUT_SEED.repeat(50)
      .slice(0, 2048)
      .replace("、", ",");
    expect(convert_sjis(overTotalLimit)).toHaveLength(4095);
    expect(() => aq.run(overTotalLimit, 300)).toThrow(
      "AquesTalk_Synthe error. ERROR CODE: 200"
    );

    const recovered = aq.run("こんにちわ");
    expect(String.fromCharCode(...recovered.slice(0, 4))).toBe("RIFF");
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

  it("returns the DLL error and recovers when guest malloc is exhausted", async () => {
    const loaded = await load("f1", { heapSize: 1200 * 1024 });
    try {
      expect(() => loaded.run("あ".repeat(50), 50)).toThrow(
        "AquesTalk_Synthe error. ERROR CODE: 101"
      );

      const recovered = loaded.run("あ", 300);
      expect(String.fromCharCode(...recovered.slice(0, 4))).toBe("RIFF");
    } finally {
      await loaded.destroy();
    }
  }, 30000);
});
