import { describe, expect, it } from "vitest";
import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { V86Emu } from "../src/v86_emu.js";
import { AquesTalk } from "../src/index.js";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("AquesTalk Multi-Voice Support", () => {
  const voices = [
    {
      name: "dvd",
      hash: "52d8c85fd29fc66937642185bde410878c239e34efd22c1fa427ea78eb7df30d",
    },
    {
      name: "f1",
      hash: "300500de9385cb49d8ade0a2cbf6e73d8615232bd4742107a28f4f4a9d8f367f",
    },
    {
      name: "f2",
      hash: "73187e460986980f8e10902272214530788db587b85a9b271d420d53f941ff31",
    },
    {
      name: "imd1",
      hash: "4865420beb1d83ed419de570eafb6df37955e956f606aa6a3be850fef458cae9",
    },
    {
      name: "jgr",
      hash: "9887c582b4689b2e3dd7efe0732cc4d7259a383298ee926557d579aea83ff82d",
    },
    {
      name: "m1",
      hash: "800e379a5145ae82daf7b38c90832a513372a2ddb8131c7477361d663fc8b048",
    },
    {
      name: "m2",
      hash: "dd246ce6866dff77dd219abc14af6f36edad74d79efeb1812ec198cb1ec09907",
    },
    {
      name: "r1",
      hash: "6e6b1cc87d7568d2448db4788020c5c47658bfeba72003d00a635ef03908c88b",
    },
  ];

  for (const voice of voices) {
    it(`should synthesize speech with ${voice.name} voice`, async () => {
      // Load zip file
      const zipPath = path.join(
        __dirname,
        "..",
        "voices",
        `${voice.name}.zip`
      );
      const zipBuf = fs.readFileSync(zipPath);
      const zip = new JSZip();
      const zipRoot = await zip.loadAsync(zipBuf);
      const dllFile = await zipRoot.files[
        `${voice.name}/AquesTalk.dll`
      ].async("arraybuffer");

      // Initialize v86 emulator with the production default memory size.
      const emu = new V86Emu();
      const wasmPath = path.join(__dirname, "..", "voices", "v86.wasm");
      await emu.init({ wasmPath });

      const aq = new AquesTalk(dllFile, emu);
      try {
        const result = aq.run("ゆっくりしていってね");

        expect(result).toBeDefined();
        expect(result.length).toBeGreaterThan(44); // MIN WAV header size

        // Check RIFF header
        const header = String.fromCharCode(...result.slice(0, 4));
        expect(header).toBe("RIFF");
        expect(createHash("sha256").update(result).digest("hex")).toBe(
          voice.hash
        );
      } finally {
        await aq.destroy();
      }
    }, 60000); // 60s timeout for each voice
  }
});
