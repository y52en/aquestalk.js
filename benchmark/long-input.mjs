import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";

import {
  DEFAULT_HEAP_SIZE,
  load,
} from "../dist/index.js";
import { convert_sjis } from "../dist/util.js";

const allVoices = ["dvd", "f1", "f2", "imd1", "jgr", "m1", "m2", "r1"];
const voices = process.env.BENCH_LONG_VOICES
  ? process.env.BENCH_LONG_VOICES.split(",")
  : allVoices;
const seed =
  "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわをん、";
const maximumInput = seed.repeat(50).slice(0, 2047);
const overTotalLimit = seed
  .repeat(50)
  .slice(0, 2048)
  .replace("、", ",");
const maximumPhrase = "あ".repeat(255);

function errorCode(operation) {
  try {
    operation();
  } catch (error) {
    const match = /ERROR CODE: (\d+)/.exec(String(error));
    if (match) return Number.parseInt(match[1], 10);
    throw error;
  }
  throw new Error("expected AquesTalk to reject the input");
}

const results = {
  node: process.version,
  heapMiB: DEFAULT_HEAP_SIZE / (1024 * 1024),
  maximumInput: {
    characters: maximumInput.length,
    sjisBytes: convert_sjis(maximumInput).length,
    speed: 50,
  },
  overTotalLimitSjisBytes: convert_sjis(overTotalLimit).length,
  maximumPhraseReadings: maximumPhrase.length,
  voices: {},
};

for (const voice of voices) {
  const aq = await load(voice);
  try {
    const started = performance.now();
    const wav = aq.run(maximumInput, 50);
    const elapsedMs = performance.now() - started;
    const phraseWav = aq.run(maximumPhrase, 300);
    const totalLimitError = errorCode(() => aq.run(overTotalLimit, 300));
    const phraseLimitError = errorCode(() => aq.run(`${maximumPhrase}あ`, 300));
    const recovered = aq.run("こんにちわ");
    const recoveryHeader = String.fromCharCode(...recovered.subarray(0, 4));
    if (totalLimitError !== 200 || phraseLimitError !== 102) {
      throw new Error(
        `${voice}: unexpected boundary errors ${totalLimitError}/${phraseLimitError}`
      );
    }
    if (recoveryHeader !== "RIFF") {
      throw new Error(`${voice}: synthesis did not recover after an error`);
    }

    results.voices[voice] = {
      elapsedMs,
      wavBytes: wav.length,
      sha256: createHash("sha256").update(wav).digest("hex"),
      maximumPhraseWavBytes: phraseWav.length,
      totalLimitError,
      phraseLimitError,
      recoveryHeader,
    };
  } finally {
    await aq.destroy();
  }
}

console.log(JSON.stringify(results, null, 2));
