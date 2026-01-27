
/// <reference path="../src/unicorn.d.ts" />
import * as fs from 'fs';
import * as path from 'path';

async function main() {
    console.log('Loading Unicorn...');
    const { loadUnicorn } = require('./setup');
    await loadUnicorn();
    console.log('Unicorn loaded.');

    // Now we can import src/index.ts because window.uc is set
    const { AquesTalk } = require('../src/index');
    const { from_bytes_uint32, to_bytes_uint32 } = require('../src/util'); // Assuming these are exported or available

    const dllPath = path.join(__dirname, '../f1/AquesTalk.dll');
    if (!fs.existsSync(dllPath)) {
        console.error(`DLL not found at ${dllPath}`);
        process.exit(1);
    }
    const dllBuffer = fs.readFileSync(dllPath);

    // Create AquesTalk instance
    // Note: AquesTalk constructor takes (file: ArrayBuffer, mu: Uc)
    // We need to pass the Unicorn instance.
    // In src/index.ts, AquesTalk uses this.#mu which is passed in constructor.
    // Also src/index.ts uses 'uc' global constant for constants like uc.PROT_ALL.

    const uc = (global as any).window.uc;
    const mu = new uc.Unicorn(uc.ARCH_X86, uc.MODE_32);

    // ArrayBuffer needed for constructor
    const dllArrayBuffer = dllBuffer.buffer.slice(dllBuffer.byteOffset, dllBuffer.byteOffset + dllBuffer.byteLength);

    const aquesTalk = new AquesTalk(dllArrayBuffer, mu);

    const text = "こんにちわ、せかい";
    const speed = 100;

    console.log(`Synthesizing text: "${text}"...`);
    const startTime = process.hrtime();

    let result: Uint8Array;
    try {
        result = aquesTalk.run(text, speed);
    } catch (e) {
        console.error("Error during synthesis:", e);
        process.exit(1);
    }

    const endTime = process.hrtime(startTime);
    const timeInMs = (endTime[0] * 1000 + endTime[1] / 1e6).toFixed(3);

    console.log(`Synthesis complete in ${timeInMs} ms`);
    console.log(`Result size: ${result.length} bytes`);

    const outputPath = path.join(__dirname, 'output_unicorn.wav'); // It's raw PCM or WAV? The dll output is usually WAV (header + PCM)
    // Based on AquesTalk usage, it returns a buffer. Usually it's a WAV file content.
    fs.writeFileSync(outputPath, result);
    console.log(`Saved output to ${outputPath}`);
}

main();
