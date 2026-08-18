import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";

import JSZip from "jszip";

const projectRoot = process.env.BENCH_ROOT
  ? pathToFileURL(`${resolve(process.env.BENCH_ROOT)}/`)
  : new URL("../", import.meta.url);
const { AquesTalk } = await import(new URL("dist/index.js", projectRoot));
const { V86Emu } = await import(new URL("dist/v86_emu.js", projectRoot));

const iterations = Number.parseInt(process.env.BENCH_ITERATIONS ?? "10", 10);
const warmups = Number.parseInt(process.env.BENCH_WARMUPS ?? "3", 10);
const yieldBetweenRuns = process.env.BENCH_YIELD === "1";
const requestedMemorySize = process.env.BENCH_MEMORY_SIZE
  ? Number.parseInt(process.env.BENCH_MEMORY_SIZE, 10)
  : undefined;

const cases = [
  { name: "short", text: "ゆっくりしていってね", speed: 100 },
  {
    name: "medium",
    text: "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほ、あいうえおかきくけこさしすせそ",
    speed: 100,
  },
  {
    name: "long-slow",
    text: "あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわをん、".repeat(2),
    speed: 50,
  },
];

function collectMemory() {
  globalThis.gc?.();
  // V8 releases unreachable WebAssembly.Memory backing stores on the second
  // full collection, so use two passes for stable post-destroy measurements.
  globalThis.gc?.();
  const usage = process.memoryUsage();
  return {
    rss: usage.rss,
    heapUsed: usage.heapUsed,
    external: usage.external,
    arrayBuffers: usage.arrayBuffers,
    maxRss: process.resourceUsage().maxRSS * 1024,
  };
}

async function collectReleasedMemory() {
  // JIT-heavy v86 instances survive several V8 collection phases. Yield
  // between passes so weak references and external-memory accounting settle.
  for (let pass = 0; pass < 5; pass += 1) {
    globalThis.gc?.();
    await new Promise(resolve => setImmediate(resolve));
  }
  return collectMemory();
}

function percentile(sorted, value) {
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * value) - 1)];
}

async function yieldToJit() {
  if (yieldBetweenRuns) await new Promise(resolve => setImmediate(resolve));
}

function summarize(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return {
    mean: values.reduce((sum, value) => sum + value, 0) / values.length,
    median: percentile(sorted, 0.5),
    p95: percentile(sorted, 0.95),
    min: sorted[0],
    max: sorted.at(-1),
  };
}

function makeIoStats() {
  return {
    readCalls: 0,
    readBytes: 0,
    writeCalls: 0,
    writeBytes: 0,
    largestWrite: 0,
  };
}

const results = {
  node: process.version,
  requestedMemorySize: requestedMemorySize ?? null,
  memorySize: null,
  iterations,
  warmups,
  yieldBetweenRuns,
  phases: {},
  cases: {},
};

results.phases.processStart = collectMemory();

const zipBytes = await readFile(new URL("voices/f1.zip", projectRoot));
const zip = await JSZip.loadAsync(zipBytes);
const dllFile = await zip.files["f1/AquesTalk.dll"].async("arraybuffer");

const emu = new V86Emu();
const initStart = performance.now();
const emulatorOptions = {
  wasmPath: new URL("voices/v86.wasm", projectRoot).pathname,
};
if (requestedMemorySize !== undefined) {
  emulatorOptions.memorySize = requestedMemorySize;
}
await emu.init(emulatorOptions);
results.memorySize =
  emu.memory_size ?? emu.cpu?.memory_size?.[0] ?? requestedMemorySize ?? null;
results.phases.emulatorInitMs = performance.now() - initStart;
results.phases.afterEmulatorInit = collectMemory();

let activeIoStats = makeIoStats();
const originalRead = emu.mem_read.bind(emu);
const originalWrite = emu.mem_write.bind(emu);
const originalReadUint32 = emu.mem_read_uint32?.bind(emu);
const originalWriteUint32 = emu.mem_write_uint32?.bind(emu);
const originalFill = emu.mem_fill?.bind(emu);
emu.mem_read = (address, size) => {
  activeIoStats.readCalls += 1;
  activeIoStats.readBytes += size;
  return originalRead(address, size);
};
emu.mem_write = (address, data) => {
  activeIoStats.writeCalls += 1;
  activeIoStats.writeBytes += data.byteLength;
  activeIoStats.largestWrite = Math.max(
    activeIoStats.largestWrite,
    data.byteLength,
  );
  return originalWrite(address, data);
};
if (originalReadUint32) {
  emu.mem_read_uint32 = (address) => {
    activeIoStats.readCalls += 1;
    activeIoStats.readBytes += 4;
    return originalReadUint32(address);
  };
}
if (originalWriteUint32) {
  emu.mem_write_uint32 = (address, value) => {
    activeIoStats.writeCalls += 1;
    activeIoStats.writeBytes += 4;
    activeIoStats.largestWrite = Math.max(activeIoStats.largestWrite, 4);
    return originalWriteUint32(address, value);
  };
}
if (originalFill) {
  emu.mem_fill = (address, size, value) => {
    activeIoStats.writeCalls += 1;
    activeIoStats.writeBytes += size;
    activeIoStats.largestWrite = Math.max(activeIoStats.largestWrite, size);
    return originalFill(address, size, value);
  };
}

const constructStart = performance.now();
const aq = new AquesTalk(dllFile, emu);
results.phases.constructMs = performance.now() - constructStart;
results.phases.constructIo = { ...activeIoStats };
results.phases.afterConstruct = collectMemory();

activeIoStats = makeIoStats();
for (let index = 0; index < warmups; index += 1) {
  aq.run(cases[index % cases.length].text, cases[index % cases.length].speed);
  await yieldToJit();
}
results.phases.warmupIo = { ...activeIoStats };
results.phases.afterWarmup = collectMemory();

for (const benchmarkCase of cases) {
  const times = [];
  const ioRuns = [];
  let outputBytes = 0;
  let checksum = "";

  for (let index = 0; index < iterations; index += 1) {
    activeIoStats = makeIoStats();
    const start = performance.now();
    const output = aq.run(benchmarkCase.text, benchmarkCase.speed);
    times.push(performance.now() - start);
    ioRuns.push(activeIoStats);
    outputBytes = output.byteLength;
    const currentChecksum = createHash("sha256").update(output).digest("hex");
    if (checksum && currentChecksum !== checksum) {
      throw new Error(`${benchmarkCase.name} produced non-deterministic output`);
    }
    checksum = currentChecksum;
    await yieldToJit();
  }

  results.cases[benchmarkCase.name] = {
    speed: benchmarkCase.speed,
    inputCharacters: benchmarkCase.text.length,
    outputBytes,
    checksum,
    timeMs: summarize(times),
    io: {
      readCalls: summarize(ioRuns.map((stats) => stats.readCalls)),
      readBytes: summarize(ioRuns.map((stats) => stats.readBytes)),
      writeCalls: summarize(ioRuns.map((stats) => stats.writeCalls)),
      writeBytes: summarize(ioRuns.map((stats) => stats.writeBytes)),
      largestWrite: Math.max(...ioRuns.map((stats) => stats.largestWrite)),
    },
  };
}

results.phases.afterBenchmarks = collectMemory();
await aq.destroy();
// Let V8 finish one collection before measuring the released WebAssembly
// backing store; its external-memory accounting otherwise lags by one pass.
results.phases.afterDestroy = await collectReleasedMemory();

console.log(JSON.stringify(results, null, 2));
