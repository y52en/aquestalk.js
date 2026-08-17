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
const soakIterations = Number.parseInt(process.env.BENCH_SOAK_ITERATIONS ?? "0", 10);
const seed =
  "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわをん、";
const maximumInput = seed.repeat(50).slice(0, 2047);
const overTotalLimit = seed
  .repeat(50)
  .slice(0, 2048)
  .replace("、", ",");
const maximumPhrase = "あ".repeat(255);
const soakCorpus = [
  { input: "こんにちわ。", speed: 100 },
  { input: "ゆっくりしていってね。", speed: 100 },
  { input: "きょーも/はいしんを+みてくれて、ありがとー。", speed: 120 },
  { input: seed.repeat(2), speed: 50 },
  { input: "あ".repeat(255), speed: 300 },
];

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

function memorySnapshot() {
  const memory = process.memoryUsage();
  return {
    rss: memory.rss,
    heapUsed: memory.heapUsed,
    external: memory.external,
    arrayBuffers: memory.arrayBuffers,
  };
}

async function collectMemory() {
  await new Promise(resolve => setImmediate(resolve));
  global.gc?.();
  await new Promise(resolve => setImmediate(resolve));
  global.gc?.();
  return memorySnapshot();
}

async function runSoak(aq, voice) {
  if (!Number.isSafeInteger(soakIterations) || soakIterations < 1) return null;
  if (typeof global.gc !== "function") {
    throw new Error("soak mode requires node --expose-gc");
  }

  // Warm both the emulator/JIT and V8 allocations before recording a baseline.
  for (let i = 0; i < 20; i += 1) {
    const sample = soakCorpus[i % soakCorpus.length];
    aq.run(sample.input, sample.speed);
    await new Promise(resolve => setImmediate(resolve));
  }
  const before = await collectMemory();
  const samples = [{ iteration: 0, ...before }];
  let lastWav = null;

  for (let i = 1; i <= soakIterations; i += 1) {
    const sample = soakCorpus[i % soakCorpus.length];
    lastWav = aq.run(sample.input, sample.speed);
    if (String.fromCharCode(...lastWav.subarray(0, 4)) !== "RIFF") {
      throw new Error(`${voice}: non-WAV result at soak iteration ${i}`);
    }

    // Give v86's async JIT finalization a chance to run, matching browser-style
    // repeated comment synthesis rather than one giant synchronous loop.
    if (i % 25 === 0) {
      await new Promise(resolve => setImmediate(resolve));
    }
    if (i % 500 === 0 || i === soakIterations) {
      lastWav = null;
      samples.push({ iteration: i, ...(await collectMemory()) });
    }
  }
  lastWav = null;
  const after = await collectMemory();
  const externalGrowth = after.external - before.external;
  const arrayBufferGrowth = after.arrayBuffers - before.arrayBuffers;

  // A single v86 instance intentionally retains its fixed guest memory and JIT
  // state. What must not happen is per-comment external/ArrayBuffer accumulation.
  const allowedGrowth = 16 * 1024 * 1024;
  if (externalGrowth > allowedGrowth || arrayBufferGrowth > allowedGrowth) {
    throw new Error(
      `${voice}: soak memory did not plateau: external +${externalGrowth}, arrayBuffers +${arrayBufferGrowth}`
    );
  }

  return {
    iterations: soakIterations,
    before,
    after,
    externalGrowth,
    arrayBufferGrowth,
    samples,
  };
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
  soakIterations,
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
      soak: await runSoak(aq, voice),
    };
  } finally {
    await aq.destroy();
  }
}

console.log(JSON.stringify(results, null, 2));
